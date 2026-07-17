/*
 * One-shot launcher for a single LTP test executable.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Elfuse models the initial guest process as PID/SID/PGID 1, and busybox
 * ash execs a lone command in place, so a test spawned directly would run
 * as the session leader and confuse the process-group assertions in tests
 * like setpgid01. This launcher forks first, so the test is always an
 * ordinary non-session-leader child, then reports what happened through a
 * single-line JSON status file written atomically (exclusive tempfile,
 * fsync, rename) next to whatever stdout the test produced.
 *
 * Exit status mirrors the child: its exit code, 128 plus the signal
 * number when it died on a signal, 127 when the exec itself failed, and
 * 125 for launcher-internal errors. Cross-compiled as a static Linux
 * AArch64 binary by the fixture builder; it never builds for the host.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "status-io.h"

#define EXIT_INTERNAL 125
#define EXIT_NO_EXEC 127

/* Publish the status JSON with a single writer and a single rename so a
 * reader either sees nothing or sees the complete line.
 */
static int write_status(const char *path,
                        bool exited,
                        int exit_code,
                        bool signaled,
                        int signum,
                        int exec_errno)
{
    char line[256];
    int len;

    if (!path)
        return 0;

    len = snprintf(line, sizeof(line),
                   "{\"schema_version\":1,\"exited\":%s,\"exit_code\":%d,"
                   "\"signaled\":%s,\"signal\":%d,\"exec_errno\":%d}\n",
                   exited ? "true" : "false", exit_code,
                   signaled ? "true" : "false", signum, exec_errno);
    if (len < 0 || (size_t) len >= sizeof(line))
        return -1;

    return publish_status_line(path, line, (size_t) len);
}

static void usage(void)
{
    fprintf(stderr,
            "usage: case-launcher [--status PATH] -- COMMAND [ARG...]\n");
}

int main(int argc, char **argv)
{
    const char *status_path = NULL;
    int arg_index = 1;
    int exec_pipe[2];
    pid_t child;
    int wait_status;
    int exec_errno = 0;
    bool exited;
    int exit_code;
    bool signaled;
    int signum;

    while (arg_index < argc) {
        if (strcmp(argv[arg_index], "--status") == 0) {
            if (arg_index + 1 >= argc) {
                usage();
                return EXIT_INTERNAL;
            }
            status_path = argv[arg_index + 1];
            arg_index += 2;
        } else if (strcmp(argv[arg_index], "--") == 0) {
            arg_index++;
            break;
        } else {
            usage();
            return EXIT_INTERNAL;
        }
    }

    if (arg_index >= argc) {
        usage();
        return EXIT_INTERNAL;
    }

    /* A dropped controlling terminal must not take the launcher down
     * before it can report; the child gets default disposition back.
     */
    signal(SIGHUP, SIG_IGN);

    if (pipe(exec_pipe) < 0) {
        perror("case-launcher: pipe");
        return EXIT_INTERNAL;
    }
    if (fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC) < 0) {
        perror("case-launcher: fcntl");
        return EXIT_INTERNAL;
    }

    child = fork();
    if (child < 0) {
        perror("case-launcher: fork");
        return EXIT_INTERNAL;
    }

    if (child == 0) {
        close(exec_pipe[0]);
        signal(SIGHUP, SIG_DFL);
        execvp(argv[arg_index], &argv[arg_index]);

        /* Exec failed: hand errno to the parent as one atomic 4-byte
         * write (below PIPE_BUF), then bail without touching stdio.
         */
        exec_errno = errno;
        (void) write_all(exec_pipe[1], &exec_errno, sizeof(exec_errno));
        _exit(EXIT_NO_EXEC);
    }

    close(exec_pipe[1]);
    if (read_full(exec_pipe[0], &exec_errno, sizeof(exec_errno)) !=
        (ssize_t) sizeof(exec_errno))
        exec_errno = 0;
    close(exec_pipe[0]);

    for (;;) {
        if (waitpid(child, &wait_status, 0) >= 0)
            break;
        if (errno == EINTR)
            continue;
        perror("case-launcher: waitpid");
        return EXIT_INTERNAL;
    }

    exited = WIFEXITED(wait_status) != 0;
    exit_code = exited ? WEXITSTATUS(wait_status) : 0;
    signaled = WIFSIGNALED(wait_status) != 0;
    signum = signaled ? WTERMSIG(wait_status) : 0;

    if (write_status(status_path, exited, exit_code, signaled, signum,
                     exec_errno) < 0) {
        perror("case-launcher: status");
        return EXIT_INTERNAL;
    }

    if (signaled)
        return 128 + signum;
    if (exec_errno != 0)
        return EXIT_NO_EXEC;
    return exit_code;
}
