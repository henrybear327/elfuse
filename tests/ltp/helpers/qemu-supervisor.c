/*
 * Root-side per-case supervisor for the QEMU reference backend.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Runs as root inside the reference VM, outside the chroot. For every
 * test command it forks a child that starts a fresh session, chroots
 * into the staged glibc rootfs, drops supplementary groups and GID/UID,
 * and execs the command; the parent enforces a monotonic deadline and,
 * once the child is gone, hunts down and reaps every descendant left in
 * the child's session so one case cannot leak processes into the next.
 *
 * The post-deadline cleanup budget is a fixed constant so the harness
 * can cap the surrounding SSH session: TERM_GRACE_SEC + KILL_WAIT_SEC +
 * REAP_POLL_SEC plus one second of slack is 12 seconds, and the channel
 * allows 20 seconds beyond the test timeout (OUTER_CAP_SLACK_SEC in
 * tests/ltp/plugins/qemuchroot_chan.py; a harness selftest asserts the
 * inequality between the two files).
 *
 * Status is a single-line JSON file published atomically (exclusive
 * tempfile, fsync, rename). Exit status: the child's own exit code,
 * 128 plus the signal number, 124 on timeout, 126 when session, chroot,
 * or privilege setup failed, 127 when the exec failed, 125 for
 * supervisor-internal errors. Cross-compiled as a static Linux AArch64
 * binary by the fixture builder; it never builds for the host.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "status-io.h"

#define EXIT_TIMEOUT 124
#define EXIT_INTERNAL 125
#define EXIT_NO_SETUP 126
#define EXIT_NO_EXEC 127

#define TERM_GRACE_SEC 5
#define KILL_WAIT_SEC 1
#define REAP_POLL_SEC 5

#define POLL_INTERVAL_NS 100000000L

/* Stage markers for the child-to-parent error pipe. */
#define STAGE_SETUP 1
#define STAGE_EXEC 2

struct child_error {
    int stage;
    int saved_errno;
};

static double monotonic_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

static void poll_sleep(void)
{
    struct timespec ts = {0, POLL_INTERVAL_NS};

    nanosleep(&ts, NULL);
}

static int write_status(const char *path,
                        bool exited,
                        int exit_code,
                        bool signaled,
                        int signum,
                        bool timed_out,
                        int exec_errno,
                        int setup_errno,
                        bool cleanup_ok)
{
    char line[320];
    int len;

    if (!path)
        return 0;

    len = snprintf(line, sizeof(line),
                   "{\"schema_version\":1,\"exited\":%s,\"exit_code\":%d,"
                   "\"signaled\":%s,\"signal\":%d,\"timed_out\":%s,"
                   "\"exec_errno\":%d,\"setup_errno\":%d,\"cleanup_ok\":%s}\n",
                   exited ? "true" : "false", exit_code,
                   signaled ? "true" : "false", signum,
                   timed_out ? "true" : "false", exec_errno, setup_errno,
                   cleanup_ok ? "true" : "false");
    if (len < 0 || (size_t) len >= sizeof(line))
        return -1;

    return publish_status_line(path, line, (size_t) len);
}

static void child_fail(int fd, int stage)
{
    struct child_error report;

    report.stage = stage;
    report.saved_errno = errno;
    (void) write_all(fd, &report, sizeof(report));
    _exit(stage == STAGE_SETUP ? EXIT_NO_SETUP : EXIT_NO_EXEC);
}

static void child_main(int error_fd,
                       const char *root,
                       const char *cwd,
                       uid_t uid,
                       gid_t gid,
                       char **cmd_argv)
{
    signal(SIGHUP, SIG_DFL);

    if (setsid() < 0)
        child_fail(error_fd, STAGE_SETUP);
    if (chroot(root) < 0)
        child_fail(error_fd, STAGE_SETUP);
    if (chdir(cwd) < 0)
        child_fail(error_fd, STAGE_SETUP);
    if (setgroups(0, NULL) < 0)
        child_fail(error_fd, STAGE_SETUP);
    if (setgid(gid) < 0)
        child_fail(error_fd, STAGE_SETUP);
    if (setuid(uid) < 0)
        child_fail(error_fd, STAGE_SETUP);
    if (setuid(0) == 0 && uid != 0) {
        /* Regaining root after the drop means the drop did not stick. */
        errno = EPERM;
        child_fail(error_fd, STAGE_SETUP);
    }

    execvp(cmd_argv[0], cmd_argv);
    child_fail(error_fd, STAGE_EXEC);
}

/* Parse the session field from /proc/<pid>/stat. The comm field may hold
 * any bytes including spaces and parens, so scanning restarts after the
 * last closing paren. Returns -1 when the process is gone or unreadable.
 */
static long read_stat_session(const char *pid_name)
{
    char path[64];
    char buf[512];
    ssize_t got;
    int fd;
    const char *cursor;
    long session;

    if (snprintf(path, sizeof(path), "/proc/%s/stat", pid_name) >=
        (int) sizeof(path))
        return -1;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    got = read_full(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (got <= 0)
        return -1;
    buf[got] = '\0';

    cursor = strrchr(buf, ')');
    if (!cursor)
        return -1;
    cursor++;

    /* Fields after comm: state ppid pgrp session ... */
    if (sscanf(cursor, " %*c %*d %*d %ld", &session) != 1)
        return -1;

    return session;
}

/* Kill every process whose session is the child's, then reap whatever
 * reparents to the supervisor (a child subreaper). Returns true when
 * the session is empty within the budget, false when stragglers
 * survive. A PID could in principle be recycled between the scan and
 * the kill; the VM runs one case at a time, so the window is accepted
 * rather than closed.
 */
static bool sweep_session(pid_t session_id)
{
    double deadline = monotonic_now() + REAP_POLL_SEC;

    for (;;) {
        DIR *proc = opendir("/proc");
        struct dirent *entry;
        int alive = 0;

        if (!proc)
            return false;

        while ((entry = readdir(proc)) != NULL) {
            long session;
            pid_t pid;

            if (!isdigit((unsigned char) entry->d_name[0]))
                continue;

            session = read_stat_session(entry->d_name);
            if (session != (long) session_id)
                continue;

            pid = (pid_t) strtol(entry->d_name, NULL, 10);
            alive++;
            (void) kill(pid, SIGKILL);
        }
        closedir(proc);

        while (waitpid(-1, NULL, WNOHANG) > 0)
            continue;

        if (!alive)
            return true;
        if (monotonic_now() >= deadline)
            return false;

        poll_sleep();
    }
}

/* Wait for the direct child up to a monotonic deadline, reaping any
 * subreaped orphans along the way. Returns true with the status filled
 * when the child exited, false on deadline expiry.
 */
static bool wait_child_until(pid_t child, double deadline, int *wait_status)
{
    for (;;) {
        pid_t reaped = waitpid(-1, wait_status, WNOHANG);

        if (reaped == child)
            return true;
        if (reaped < 0 && errno != ECHILD && errno != EINTR) {
            perror("qemu-supervisor: waitpid");
            _exit(EXIT_INTERNAL);
        }
        if (reaped <= 0) {
            /* ECHILD lands here too: the direct child can only vanish
             * through the waitpid above, so an unexpected ECHILD means
             * a wait raced and polling until the deadline stays safe.
             */
            if (monotonic_now() >= deadline)
                return false;
            poll_sleep();
        }
    }
}

/* Strict decimal parse: "0" stays 0, but "abc" must not turn into uid 0. */
static long parse_nonneg(const char *text)
{
    char *end = NULL;
    long value;

    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0)
        return -1;

    return value;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: qemu-supervisor --root DIR --cwd DIR --uid N --gid N\n"
            "                       --timeout SECONDS --status PATH --\n"
            "                       COMMAND [ARG...]\n");
}

int main(int argc, char **argv)
{
    const char *root = NULL;
    const char *cwd = NULL;
    const char *status_path = NULL;
    long uid = -1;
    long gid = -1;
    long timeout_sec = -1;
    int arg_index = 1;
    int error_pipe[2];
    struct child_error child_report = {0, 0};
    pid_t child;
    int wait_status = 0;
    bool timed_out = false;
    bool cleanup_ok;
    bool exited;
    int exit_code;
    bool signaled;
    int signum;

    while (arg_index + 1 < argc && argv[arg_index][0] == '-') {
        const char *opt = argv[arg_index];
        const char *val = argv[arg_index + 1];

        if (strcmp(opt, "--") == 0)
            break;
        if (strcmp(opt, "--root") == 0)
            root = val;
        else if (strcmp(opt, "--cwd") == 0)
            cwd = val;
        else if (strcmp(opt, "--uid") == 0)
            uid = parse_nonneg(val);
        else if (strcmp(opt, "--gid") == 0)
            gid = parse_nonneg(val);
        else if (strcmp(opt, "--timeout") == 0)
            timeout_sec = parse_nonneg(val);
        else if (strcmp(opt, "--status") == 0)
            status_path = val;
        else {
            usage();
            return EXIT_INTERNAL;
        }
        arg_index += 2;
    }

    if (arg_index < argc && strcmp(argv[arg_index], "--") == 0)
        arg_index++;

    if (!root || !cwd || !status_path || uid < 0 || gid < 0 ||
        timeout_sec <= 0 || arg_index >= argc) {
        usage();
        return EXIT_INTERNAL;
    }
    if (cwd[0] != '/') {
        fprintf(stderr, "qemu-supervisor: --cwd must be absolute\n");
        return EXIT_INTERNAL;
    }

    /* Ignore SIGHUP before forking: a dying SSH transport must not kill
     * the supervisor mid-cleanup. The child restores the default.
     */
    signal(SIGHUP, SIG_IGN);

    if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
        perror("qemu-supervisor: prctl");
        return EXIT_INTERNAL;
    }

    if (pipe(error_pipe) < 0) {
        perror("qemu-supervisor: pipe");
        return EXIT_INTERNAL;
    }
    if (fcntl(error_pipe[1], F_SETFD, FD_CLOEXEC) < 0) {
        perror("qemu-supervisor: fcntl");
        return EXIT_INTERNAL;
    }

    child = fork();
    if (child < 0) {
        perror("qemu-supervisor: fork");
        return EXIT_INTERNAL;
    }

    if (child == 0) {
        close(error_pipe[0]);
        child_main(error_pipe[1], root, cwd, (uid_t) uid, (gid_t) gid,
                   &argv[arg_index]);
    }

    close(error_pipe[1]);

    if (!wait_child_until(child, monotonic_now() + (double) timeout_sec,
                          &wait_status)) {
        timed_out = true;

        /* The child leads its own session and process group (setsid),
         * so the group id is the child pid even in the shared pid
         * namespace.
         */
        (void) kill(-child, SIGTERM);
        if (!wait_child_until(child, monotonic_now() + TERM_GRACE_SEC,
                              &wait_status)) {
            (void) kill(-child, SIGKILL);
            if (!wait_child_until(child, monotonic_now() + KILL_WAIT_SEC,
                                  &wait_status)) {
                /* An unkillable (D-state) child; report and move on
                 * rather than blocking past the SSH cap.
                 */
                write_status(status_path, false, 0, false, 0, true, 0, 0,
                             false);
                return EXIT_TIMEOUT;
            }
        }
    }

    if (read_full(error_pipe[0], &child_report, sizeof(child_report)) !=
        (ssize_t) sizeof(child_report)) {
        child_report.stage = 0;
        child_report.saved_errno = 0;
    }
    close(error_pipe[0]);

    cleanup_ok = sweep_session(child);

    exited = WIFEXITED(wait_status) != 0;
    exit_code = exited ? WEXITSTATUS(wait_status) : 0;
    signaled = WIFSIGNALED(wait_status) != 0;
    signum = signaled ? WTERMSIG(wait_status) : 0;

    if (write_status(
            status_path, exited, exit_code, signaled, signum, timed_out,
            child_report.stage == STAGE_EXEC ? child_report.saved_errno : 0,
            child_report.stage == STAGE_SETUP ? child_report.saved_errno : 0,
            cleanup_ok) < 0) {
        perror("qemu-supervisor: status");
        return EXIT_INTERNAL;
    }

    if (timed_out)
        return EXIT_TIMEOUT;
    if (!cleanup_ok)
        return EXIT_INTERNAL;
    if (child_report.stage == STAGE_SETUP)
        return EXIT_NO_SETUP;
    if (child_report.stage == STAGE_EXEC)
        return EXIT_NO_EXEC;
    if (signaled)
        return 128 + signum;
    return exit_code;
}
