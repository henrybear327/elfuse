/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Run outside the chroot as root. The child starts a session, chroots, and
 * drops credentials; the parent enforces a deadline and reaps that session.
 * Replace the JSON status atomically so readers see a complete record.
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

#define EXIT_TIMEOUT 124
#define EXIT_INTERNAL 125
#define EXIT_NO_SETUP 126
#define EXIT_NO_EXEC 127

#define TERM_GRACE_SEC 5
#define KILL_WAIT_SEC 1
#define REAP_POLL_SEC 5
#define POLL_INTERVAL_NS 100000000L

#define STAGE_SETUP 1
#define STAGE_EXEC 2

struct child_error {
    int stage;
    int saved_errno;
};

static double now(void)
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

static ssize_t write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    size_t done = 0;

    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        done += (size_t) n;
    }
    return (ssize_t) done;
}

static ssize_t read_full(int fd, void *buf, size_t len)
{
    char *p = buf;
    size_t done = 0;

    while (done < len) {
        ssize_t n = read(fd, p + done, len - done);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break;
        done += (size_t) n;
    }
    return (ssize_t) done;
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
    char tmp[4096];
    int len;
    int fd;

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
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int) sizeof(tmp))
        return -1;
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
        return -1;
    if (write_all(fd, line, (size_t) len) < 0 || fsync(fd) < 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    close(fd);
    return rename(tmp, path);
}

static void child_fail(int fd, int stage)
{
    struct child_error report = {stage, errno};

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
    if (setsid() < 0 || chroot(root) < 0 || chdir(cwd) < 0 ||
        setgroups(0, NULL) < 0 || setgid(gid) < 0 || setuid(uid) < 0)
        child_fail(error_fd, STAGE_SETUP);
    if (uid != 0 && setuid(0) == 0) {
        /* Regaining root means the drop did not stick. */
        errno = EPERM;
        child_fail(error_fd, STAGE_SETUP);
    }
    execvp(cmd_argv[0], cmd_argv);
    child_fail(error_fd, STAGE_EXEC);
}

/* comm may contain spaces and parens, so parse fields after its last ')'. */
static long stat_session(const char *pid_name)
{
    char path[64];
    char buf[512];
    const char *cursor;
    ssize_t got;
    long session;
    int fd;

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
    if (sscanf(cursor + 1, " %*c %*d %*d %ld", &session) != 1)
        return -1;
    return session;
}

/* The serialized VM accepts PID reuse between the session scan and kill. */
static bool sweep_session(pid_t session_id)
{
    double deadline = now() + REAP_POLL_SEC;

    for (;;) {
        DIR *proc = opendir("/proc");
        struct dirent *entry;
        int alive = 0;

        if (!proc)
            return false;
        while ((entry = readdir(proc)) != NULL) {
            if (!isdigit((unsigned char) entry->d_name[0]))
                continue;
            if (stat_session(entry->d_name) != (long) session_id)
                continue;
            alive++;
            (void) kill((pid_t) strtol(entry->d_name, NULL, 10), SIGKILL);
        }
        closedir(proc);
        while (waitpid(-1, NULL, WNOHANG) > 0)
            continue;
        if (!alive)
            return true;
        if (now() >= deadline)
            return false;
        poll_sleep();
    }
}

/* Reap orphans while waiting; only this loop can reap the direct child. */
static bool wait_child_until(pid_t child, double deadline, int *status)
{
    for (;;) {
        pid_t reaped = waitpid(-1, status, WNOHANG);

        if (reaped == child)
            return true;
        if (reaped < 0 && errno != ECHILD && errno != EINTR) {
            perror("guest-supervisor: waitpid");
            _exit(EXIT_INTERNAL);
        }
        if (reaped <= 0) {
            if (now() >= deadline)
                return false;
            poll_sleep();
        }
    }
}

/* Strict decimal parse: "0" stays 0, and "abc" must not become uid 0. */
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
            "usage: guest-supervisor --root DIR --cwd DIR --uid N --gid N\n"
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
    struct child_error report = {0, 0};
    pid_t child;
    int status = 0;
    bool timed_out = false;
    bool cleanup_ok;

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
        timeout_sec <= 0 || arg_index >= argc || cwd[0] != '/') {
        usage();
        return EXIT_INTERNAL;
    }

    /* A dying ssh transport must not kill the supervisor mid-cleanup. */
    signal(SIGHUP, SIG_IGN);
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0 || pipe(error_pipe) < 0 ||
        fcntl(error_pipe[1], F_SETFD, FD_CLOEXEC) < 0) {
        perror("guest-supervisor: setup");
        return EXIT_INTERNAL;
    }

    child = fork();
    if (child < 0) {
        perror("guest-supervisor: fork");
        return EXIT_INTERNAL;
    }
    if (child == 0) {
        close(error_pipe[0]);
        child_main(error_pipe[1], root, cwd, (uid_t) uid, (gid_t) gid,
                   &argv[arg_index]);
    }
    close(error_pipe[1]);

    if (!wait_child_until(child, now() + (double) timeout_sec, &status)) {
        timed_out = true;
        /* The child leads its own group (setsid), so -child names it. */
        (void) kill(-child, SIGTERM);
        if (!wait_child_until(child, now() + TERM_GRACE_SEC, &status)) {
            (void) kill(-child, SIGKILL);
            if (!wait_child_until(child, now() + KILL_WAIT_SEC, &status)) {
                /* An unkillable D-state child: report and move on. */
                write_status(status_path, false, 0, false, 0, true, 0, 0,
                             false);
                return EXIT_TIMEOUT;
            }
        }
    }

    if (read_full(error_pipe[0], &report, sizeof(report)) !=
        (ssize_t) sizeof(report))
        report.stage = 0;
    close(error_pipe[0]);
    cleanup_ok = sweep_session(child);

    if (write_status(status_path, WIFEXITED(status) != 0,
                     WIFEXITED(status) ? WEXITSTATUS(status) : 0,
                     WIFSIGNALED(status) != 0,
                     WIFSIGNALED(status) ? WTERMSIG(status) : 0, timed_out,
                     report.stage == STAGE_EXEC ? report.saved_errno : 0,
                     report.stage == STAGE_SETUP ? report.saved_errno : 0,
                     cleanup_ok) < 0) {
        perror("guest-supervisor: status");
        return EXIT_INTERNAL;
    }
    if (timed_out)
        return EXIT_TIMEOUT;
    if (!cleanup_ok)
        return EXIT_INTERNAL;
    if (report.stage == STAGE_SETUP)
        return EXIT_NO_SETUP;
    if (report.stage == STAGE_EXEC)
        return EXIT_NO_EXEC;
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return WEXITSTATUS(status);
}
