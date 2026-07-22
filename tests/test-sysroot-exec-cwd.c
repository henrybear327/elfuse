/*
 * Sysroot guest cwd across fork/exec regression test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A plain-directory sysroot on a case-insensitive volume stores guest-created
 * names as sidecar ".ef_<hex>" tokens. The guest cwd must never leak those
 * token names: after chdir into a guest-created directory, getcwd() and
 * /proc/self/cwd must report the guest path both in the calling process and
 * in a forked child after execve (the fork relaunches elfuse, whose lazily
 * recomputed cwd must reverse-map tokens back to the guest name).
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define WORK_DIR "/exec-cwd-work"
#define NESTED_DIR WORK_DIR "/Nested"

static void check_cwd(const char *ctx)
{
    char cwd[512];
    char proc_cwd[512];
    ssize_t len;

    TEST("getcwd reports guest path");
    if (!getcwd(cwd, sizeof(cwd))) {
        FAIL("getcwd failed");
    } else if (strcmp(cwd, NESTED_DIR) != 0) {
        printf("[%s: getcwd said '%s'] ", ctx, cwd);
        FAIL("getcwd leaked a non-guest path");
    } else {
        PASS();
    }

    TEST("cwd has no sidecar token");
    if (!getcwd(cwd, sizeof(cwd))) {
        FAIL("getcwd failed");
    } else if (strstr(cwd, ".ef_")) {
        FAIL("getcwd leaked a sidecar token name");
    } else {
        PASS();
    }

    TEST("/proc/self/cwd reports guest path");
    len = readlink("/proc/self/cwd", proc_cwd, sizeof(proc_cwd) - 1);
    if (len < 0) {
        FAIL("readlink /proc/self/cwd failed");
    } else {
        proc_cwd[len] = '\0';
        if (strcmp(proc_cwd, NESTED_DIR) != 0) {
            printf("[%s: /proc/self/cwd said '%s'] ", ctx, proc_cwd);
            FAIL("/proc/self/cwd leaked a non-guest path");
        } else {
            PASS();
        }
    }
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--check")) {
        printf("test-sysroot-exec-cwd: forked child checks\n");
        check_cwd("child");
        SUMMARY("test-sysroot-exec-cwd child");
        return fails > 0 ? 1 : 0;
    }

    printf("test-sysroot-exec-cwd: guest cwd across fork/exec\n");

    TEST("mkdir guest work dirs");
    /* The directories must be created by the guest: only guest-created
     * names get sidecar tokens on a case-insensitive plain-dir sysroot,
     * and the token spelling must never surface in the reported cwd.
     */
    if (mkdir(WORK_DIR, 0755) < 0 || mkdir(NESTED_DIR, 0755) < 0)
        FAIL("mkdir failed");
    else
        PASS();

    TEST("chdir into nested guest dir");
    if (chdir(NESTED_DIR) < 0)
        FAIL("chdir failed");
    else
        PASS();

    check_cwd("parent");

    TEST("relative access sees guest-created file");
    /* faccessat with a relative path must resolve through the sidecar
     * index like openat does: the file exists on disk only under its
     * token name, so a raw host lookup of the guest name reports ENOENT.
     */
    {
        int fd = open("t-file", O_CREAT | O_WRONLY, 0644);
        if (fd < 0) {
            FAIL("create t-file failed");
        } else {
            close(fd);
            if (access("t-file", F_OK) != 0)
                FAIL("access t-file failed");
            else
                PASS();
        }
    }

    char self[512];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n < 0) {
        perror("readlink /proc/self/exe");
        return 1;
    }
    self[n] = '\0';

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        char *child_argv[] = {self, "--check", NULL};
        execve(self, child_argv, NULL);
        perror("execve");
        _exit(127);
    }

    int status = 0;
    TEST("forked child passes its checks");
    if (waitpid(pid, &status, 0) < 0)
        FAIL("waitpid failed");
    else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        FAIL("child cwd checks failed");
    else
        PASS();

    SUMMARY("test-sysroot-exec-cwd");
    return fails > 0 ? 1 : 0;
}
