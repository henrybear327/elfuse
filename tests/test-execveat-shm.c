/*
 * execveat + /dev/shm nofollow
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * sc_execveat must open a /dev/shm leaf with O_NOFOLLOW, matching direct
 * sys_execve, so a symlink planted in the synthetic /dev/shm namespace cannot
 * resolve its target out of the namespace. Two cases:
 *   (a) a real binary copied into /dev/shm still execs (nofollow does not
 *       break the ordinary, non-symlink path);
 *   (b) a /dev/shm symlink to a binary outside the namespace fails with ELOOP
 *       instead of being followed and executed.
 * The binary re-execs itself with --phase2 as the "executed successfully"
 * payload, which just exits 0.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

#define SHM_EXEC "/dev/shm/EfuseShmExec"
#define SHM_LINK "/dev/shm/EfuseShmLink"
#define SHM_FIFO "/dev/shm/EfuseShmFifo"

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--phase2"))
        return 0;

    const char *self = argv[0];
    char *payload[] = {(char *) "shm-exec", (char *) "--phase2", NULL};

    /* The symlink fence needs an absolute target so that, if the leaf were
     * followed, execve would actually run a valid binary (exit 0), cleanly
     * distinct from the O_NOFOLLOW refusal (ELOOP). A relative argv[0] would
     * resolve against the link's directory, breaking either way and masking
     * the difference.
     */
    char abs_self[4096];
    if (self[0] == '/') {
        snprintf(abs_self, sizeof(abs_self), "%s", self);
    } else {
        char cwd[4096];
        if (!getcwd(cwd, sizeof(cwd)))
            return 1;
        snprintf(abs_self, sizeof(abs_self), "%s/%s", cwd, self);
    }

    TEST("copy self into /dev/shm");
    EXPECT_TRUE(copy_file_exec(self, SHM_EXEC) == 0, "copy into shm");

    /* (a) A regular shm binary must still exec through execveat. */
    TEST("execveat regular /dev/shm binary");
    pid_t pid = fork();
    if (pid == 0) {
        syscall(SYS_execveat, AT_FDCWD, SHM_EXEC, payload, NULL, 0);
        _exit(98);
    }
    int status = 0;
    EXPECT_TRUE(pid > 0 && waitpid(pid, &status, 0) == pid &&
                    WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "regular shm exec runs");

    /* (b) A shm symlink pointing at a binary outside the namespace must not be
     * followed: execveat must fail with ELOOP. The target is this very binary
     * (a valid executable), so if nofollow were missing the child would exec it
     * and exit 0, failing the assertion below.
     */
    if (symlink(abs_self, SHM_LINK) != 0) {
        TEST("execveat /dev/shm symlink nofollow");
        printf("SKIP (cannot create /dev/shm symlink: errno=%d)\n", errno);
    } else {
        TEST("execveat /dev/shm symlink refused");
        pid = fork();
        if (pid == 0) {
            syscall(SYS_execveat, AT_FDCWD, SHM_LINK, payload, NULL, 0);
            /* execveat returned, so it refused to follow: report ELOOP as 42.
             */
            _exit(errno == ELOOP ? 42 : 43);
        }
        status = 0;
        EXPECT_TRUE(pid > 0 && waitpid(pid, &status, 0) == pid &&
                        WIFEXITED(status) && WEXITSTATUS(status) == 42,
                    "shm symlink leaf not followed (ELOOP)");
        unlink(SHM_LINK);
    }

    /* truncate(2) and chdir(2) have no nofollow path variant, so they reach a
     * shm leaf through an fd opened with the namespace's forced flags. These
     * assert the two invariants those flags buy, which the execveat cases above
     * do not reach: a symlink leaf must not be followed out of the namespace,
     * and a FIFO leaf must not park the vCPU thread on an open with no peer.
     */
    if (symlink("/etc/hosts", SHM_LINK) != 0) {
        TEST("shm symlink truncate/chdir nofollow");
        printf("SKIP (cannot create /dev/shm symlink: errno=%d)\n", errno);
    } else {
        TEST("truncate shm symlink refused");
        EXPECT_TRUE(truncate(SHM_LINK, 0) != 0 && errno == ELOOP,
                    "symlink leaf must not be followed");

        TEST("chdir shm symlink refused");
        EXPECT_TRUE(chdir(SHM_LINK) != 0, "symlink leaf must not be followed");
        unlink(SHM_LINK);
    }

    if (mknod(SHM_FIFO, S_IFIFO | 0644, 0) != 0) {
        TEST("shm FIFO leaf does not block");
        printf("SKIP (cannot create /dev/shm FIFO: errno=%d)\n", errno);
    } else {
        /* Reaching either assertion at all is the result under test: without
         * O_NONBLOCK the open would never return and the lane would time out.
         * Linux truncate(2) on a FIFO reports EINVAL.
         */
        TEST("truncate shm FIFO returns");
        EXPECT_TRUE(truncate(SHM_FIFO, 0) != 0 && errno == EINVAL,
                    "FIFO truncate must report EINVAL, not block");

        TEST("chdir shm FIFO returns");
        EXPECT_TRUE(chdir(SHM_FIFO) != 0, "FIFO chdir must return, not block");
        unlink(SHM_FIFO);
    }

    unlink(SHM_EXEC);
    SUMMARY("test-execveat-shm");
    return fails > 0 ? 1 : 0;
}
