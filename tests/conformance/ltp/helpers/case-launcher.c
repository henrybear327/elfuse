/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Fork before exec so elfuse's PID 1 is not the test's session leader. Mirror
 * the child's exit code or 128 plus its signal.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXIT_INTERNAL 125
#define EXIT_NO_EXEC 127

int main(int argc, char **argv)
{
    pid_t child;
    int status;

    if (argc < 3 || strcmp(argv[1], "--") != 0) {
        fprintf(stderr, "usage: case-launcher -- COMMAND [ARG...]\n");
        return EXIT_INTERNAL;
    }

    /* Survive a lost controlling terminal long enough to report status. */
    signal(SIGHUP, SIG_IGN);

    child = fork();
    if (child < 0) {
        perror("case-launcher: fork");
        return EXIT_INTERNAL;
    }
    if (child == 0) {
        signal(SIGHUP, SIG_DFL);
        execvp(argv[2], &argv[2]);
        perror("case-launcher: exec");
        _exit(EXIT_NO_EXEC);
    }

    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            perror("case-launcher: waitpid");
            return EXIT_INTERNAL;
        }
    }
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return WEXITSTATUS(status);
}
