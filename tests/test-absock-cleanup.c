/*
 * absock namespace lifecycle
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Over-long pathname AF_UNIX socket addresses divert their host path through a
 * shortening symlink in a shared /tmp/elfuse-absock-<nsid> directory. The
 * namespace is shared across a forked guest tree (children inherit the root's
 * namespace id), so neither exit order may destroy state the other side still
 * needs. Both orders are covered:
 *   default mode, child exits first: the parent binds an over-long socket, a
 *   forked child binds its own and exits, and the parent's getsockname must
 *   still reverse-map to the guest spelling after the child is reaped;
 *   "owner-sweep" mode, root exits first: see owner_sweep_mode() below.
 * The companion recipe check asserts the namespace dir does not leak after the
 * guest exits.
 *
 * Needs a plain-dir sysroot on a case-insensitive volume: the four tokenized
 * levels below push the host path past the 104-byte macOS sun_path so the
 * shortening link is actually created, while the guest spelling stays under
 * the 108-byte Linux limit.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

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

#define ROOT_ABS "\0absock-cleanup-root"
#define CHILD_ABS "\0absock-cleanup-child"
#define ABS_LEN(name) \
    ((socklen_t) (offsetof(struct sockaddr_un, sun_path) + sizeof(name) - 1))

static void abs_addr(struct sockaddr_un *un, const char *name, size_t len)
{
    memset(un, 0, sizeof(*un));
    un->sun_family = AF_UNIX;
    memcpy(un->sun_path, name, len);
}

static int bind_abstract(const char *name, size_t len)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un un;
    abs_addr(&un, name, len);
    socklen_t alen = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + len);
    if (bind(fd, (struct sockaddr *) &un, alen) < 0 || listen(fd, 64) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Root-exits-first: the root binds before forking, so it creates and owns the
 * namespace dir, and its exit sweep runs while the child is still alive. The
 * sweep walks the shared dir, where the child's abstract-socket backing file
 * also lives, so an indiscriminate unlink destroys a socket the child still has
 * bound and listening. The root cannot report the outcome because it must exit
 * first, and the child cannot report it through the exit status either, since
 * the runtime reports the root's. It prints a marker line the recipe greps for;
 * a verdict file would be sidecar-tokenized and unreadable by name from the
 * host side.
 */
static int owner_sweep_mode(void)
{
    int ready[2], gone[2];
    if (pipe(ready) < 0 || pipe(gone) < 0)
        return 1;

    if (bind_abstract(ROOT_ABS, sizeof(ROOT_ABS) - 1) < 0)
        return 1;

    pid_t pid = fork();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        close(ready[0]);
        close(gone[1]);
        bool ok = bind_abstract(CHILD_ABS, sizeof(CHILD_ABS) - 1) >= 0;
        if (write(ready[1], "r", 1) != 1)
            _exit(1);

        /* The read returns 0 (EOF) once the root dies and its write end is
         * closed, so the reconnect below races nothing.
         */
        char b;
        if (read(gone[0], &b, 1) != 0)
            _exit(1);

        struct sockaddr_un un;
        abs_addr(&un, CHILD_ABS, sizeof(CHILD_ABS) - 1);
        int c = socket(AF_UNIX, SOCK_STREAM, 0);
        ok = ok && c >= 0 &&
             connect(c, (struct sockaddr *) &un, ABS_LEN(CHILD_ABS)) == 0;

        const char *msg = ok ? "OWNER_SWEEP=ok\n" : "OWNER_SWEEP=swept\n";
        if (write_fd_all(1, msg, strlen(msg)) < 0)
            _exit(1);
        _exit(ok ? 0 : 3);
    }

    close(ready[1]);
    close(gone[0]);
    char b;
    if (read(ready[0], &b, 1) != 1)
        return 1;
    /* exit(), not _exit(): the sweep under test is an atexit handler. */
    exit(0);
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "owner-sweep"))
        return owner_sweep_mode();

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
