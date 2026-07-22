/*
 * absock namespace lifecycle
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Over-long pathname AF_UNIX socket addresses divert their host path through a
 * shortening symlink in a shared /tmp/elfuse-absock-<nsid> directory. The
 * namespace is shared across a forked guest tree (children inherit the root's
 * namespace id), so a child exiting must not sweep the links its parent still
 * uses. This test binds an over-long socket in the parent, forks a child that
 * binds its own over-long socket and exits, and re-checks that the parent's
 * getsockname still reverse-maps to the guest spelling after the child is
 * reaped. The companion recipe check asserts the namespace dir does not leak
 * after the guest exits.
 *
 * Needs a plain-dir sysroot on a case-insensitive volume: the four tokenized
 * levels below push the host path past the 104-byte macOS sun_path so the
 * shortening link is actually created, while the guest spelling stays under
 * the 108-byte Linux limit.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define DEEP_DIR "/Deep.A/Deep.B/Deep.C/Deep.D"

static int bind_pathname(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un un = {0};
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, path, sizeof(un.sun_path) - 1);
    if (bind(fd, (struct sockaddr *) &un, sizeof(un)) < 0 ||
        listen(fd, 1) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool getsockname_is(int fd, const char *expect)
{
    struct sockaddr_un got = {0};
    socklen_t len = sizeof(got);
    return getsockname(fd, (struct sockaddr *) &got, &len) == 0 &&
           strcmp(got.sun_path, expect) == 0;
}

int main(void)
{
    TEST("deep tokenized chain mkdir");
    bool deep =
        (mkdir("/Deep.A", 0755) == 0 || errno == EEXIST) &&
        (mkdir("/Deep.A/Deep.B", 0755) == 0 || errno == EEXIST) &&
        (mkdir("/Deep.A/Deep.B/Deep.C", 0755) == 0 || errno == EEXIST) &&
        (mkdir(DEEP_DIR, 0755) == 0 || errno == EEXIST);
    EXPECT_TRUE(deep, "mkdir deep chain");

    TEST("parent over-long bind");
    int pfd = bind_pathname(DEEP_DIR "/Parent.Sock");
    EXPECT_TRUE(pfd >= 0, "parent bind+listen");

    TEST("parent getsockname before fork");
    EXPECT_TRUE(pfd >= 0 && getsockname_is(pfd, DEEP_DIR "/Parent.Sock"),
                "parent name round-trips");

    /* The child binds its own over-long socket, so it too creates a shortening
     * link in the shared namespace dir, then exits. Its exit sweep must leave
     * the parent's link alone.
     */
    TEST("child binds over-long and exits");
    pid_t pid = fork();
    if (pid == 0) {
        int cfd = bind_pathname(DEEP_DIR "/Child.Sock");
        _exit(cfd >= 0 ? 0 : 1);
    }
    int status = 0;
    EXPECT_TRUE(pid > 0 && waitpid(pid, &status, 0) == pid &&
                    WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "child bound and exited cleanly");

    TEST("parent getsockname after child exit");
    EXPECT_TRUE(pfd >= 0 && getsockname_is(pfd, DEEP_DIR "/Parent.Sock"),
                "sibling exit must not remove the parent's shortening link");
    if (pfd >= 0)
        close(pfd);

    SUMMARY("test-absock-cleanup");
    return fails > 0 ? 1 : 0;
}
