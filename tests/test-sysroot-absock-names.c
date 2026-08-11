/*
 * Pathname AF_UNIX sockets under a case-fold sysroot
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A pathname socket's address is a filesystem path, and it must resolve like
 * one: through the sysroot, with the same escape rules as open(2), so bind,
 * stat, connect, and unlink all agree on which file a name means. The address
 * read back through getsockname/getpeername must carry the guest's bytes,
 * never the sysroot prefix or a stored spelling.
 *
 * Linux contract pinned: unix(7). Binding to a pathname creates a socket
 * file at that path in the caller's namespace, colliding names are distinct
 * files, rebinding an in-use path is EADDRINUSE, and the full 108-byte
 * sun_path budget is the guest's.
 *
 * Code under test: net_sockaddr_to_mac / net_sockaddr_from_mac in
 * src/syscall/net-absock.c and their call sites in src/syscall/net.c and
 * src/syscall/net-msg.c. A regression shows up as bind reporting ENOENT for a
 * directory the guest created, the socket file landing at a host-literal path
 * outside the sysroot, or getsockname returning sysroot-prefixed bytes, which
 * is how a D-Bus- or X-style rendezvous between two guest processes stops
 * working.
 *
 * Run under --sysroot on a case-folding volume.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

#define DIR_S "/sockdir"

/* Connect to @path, send @token, report what the peer heard through
 * @accepted on the listener side.
 */
static int connect_send(const char *path, char token)
{
    struct sockaddr_un sa;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) != 0 ||
        write(fd, &token, 1) != 1) {
        close(fd);
        return -1;
    }
    return fd;
}

static char accept_token(int listener)
{
    char token = '?';
    int c = accept(listener, NULL, NULL);

    if (c < 0)
        return token;
    if (read(c, &token, 1) != 1)
        token = '?';
    close(c);
    return token;
}

int main(void)
{
    char path[PATH_MAX];
    struct sockaddr_un sa;
    socklen_t slen;
    struct stat st;
    int lfd, cfd;

    printf("test-sysroot-absock-names: pathname sockets in the sysroot\n");

    TEST("fixture mkdir");
    EXPECT_TRUE(mkdir(DIR_S, 0755) == 0 || errno == EEXIST, "mkdir");

    /* The address is a path: it must land inside the sysroot, in a directory
     * only the guest namespace holds.
     */
    TEST("bind creates a socket inside the sysroot");
    snprintf(path, sizeof(path), "%s/My.Sock", DIR_S);
    lfd = unix_bind(path, SOCK_STREAM, 4);
    EXPECT_TRUE(lfd >= 0, "bind + listen");

    TEST("getsockname returns the exact guest bytes");
    memset(&sa, 0, sizeof(sa));
    slen = sizeof(sa);
    if (lfd < 0) {
        FAIL("no listener");
    } else if (getsockname(lfd, (struct sockaddr *) &sa, &slen) != 0) {
        FAIL("getsockname");
    } else {
        EXPECT_TRUE(!strncmp(sa.sun_path, path, sizeof(sa.sun_path)),
                    "address leaked a host spelling");
        if (strncmp(sa.sun_path, path, sizeof(sa.sun_path)))
            fprintf(stderr, "  got %.*s\n", (int) sizeof(sa.sun_path),
                    sa.sun_path);
    }

    /* bind and the path layer must agree on which file the name means. */
    TEST("stat sees the bound socket");
    EXPECT_TRUE(stat(path, &st) == 0 && S_ISSOCK(st.st_mode), "stat");

    TEST("a second socket connects and a byte round-trips");
    cfd = connect_send(path, 'a');
    EXPECT_TRUE(cfd >= 0 && accept_token(lfd) == 'a', "connect + read");
    if (cfd >= 0)
        close(cfd);

    TEST("rebinding an in-use name is EADDRINUSE");
    {
        int fd2 = socket(AF_UNIX, SOCK_STREAM, 0);
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
        errno = 0;
        EXPECT_TRUE(fd2 >= 0 &&
                        bind(fd2, (struct sockaddr *) &sa, sizeof(sa)) != 0 &&
                        errno == EADDRINUSE,
                    "should be EADDRINUSE");
        if (fd2 >= 0)
            close(fd2);
    }

    /* Names differing only by case are distinct sockets, each reachable by
     * its own spelling: one stored literally, one escaped.
     */
    TEST("case-colliding socket names coexist");
    {
        char lower[PATH_MAX], upper[PATH_MAX];
        int lfd2, lfd3, c1, c2;

        snprintf(lower, sizeof(lower), "%s/sock", DIR_S);
        snprintf(upper, sizeof(upper), "%s/Sock", DIR_S);
        lfd2 = unix_bind(lower, SOCK_STREAM, 4);
        lfd3 = unix_bind(upper, SOCK_STREAM, 4);
        if (lfd2 < 0 || lfd3 < 0) {
            FAIL("bind pair");
        } else {
            TEST("  and each spelling reaches its own listener");
            c1 = connect_send(lower, 'l');
            c2 = connect_send(upper, 'u');
            EXPECT_TRUE(c1 >= 0 && c2 >= 0 && accept_token(lfd2) == 'l' &&
                            accept_token(lfd3) == 'u',
                        "wrong listener answered");
            if (c1 >= 0)
                close(c1);
            if (c2 >= 0)
                close(c2);
        }
        if (lfd2 >= 0)
            close(lfd2);
        if (lfd3 >= 0)
            close(lfd3);
    }

    /* recvmsg reports a datagram's source address, and the length it reports
     * has to describe the bytes it wrote: the guest spelling, which is what
     * the translation hands back. A host spelling is longer, so a guest
     * sizing the path as msg_namelen - offsetof(sun_path) reads past the
     * address into whatever its own buffer held. recvmsg used to report the
     * macOS length while writing the translated address, which the other
     * three readback paths (accept, getsockname and recvfrom) never did.
     * Both sockets are bound, because an unbound sender has no address for
     * the receiver to be told about.
     */
    TEST("recvmsg reports the guest address length");
    {
        char sender[PATH_MAX];
        struct sockaddr_un from;
        struct msghdr msg;
        struct iovec iov;
        char byte = 'd';
        int rfd, sfd;

        snprintf(path, sizeof(path), "%s/Recv.Sock", DIR_S);
        snprintf(sender, sizeof(sender), "%s/Sender.Sock", DIR_S);
        rfd = unix_bind(path, SOCK_DGRAM, 0);
        sfd = unix_bind(sender, SOCK_DGRAM, 0);
        if (rfd < 0 || sfd < 0) {
            FAIL("bind dgram pair");
        } else {
            memset(&sa, 0, sizeof(sa));
            sa.sun_family = AF_UNIX;
            snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
            memset(&from, 0, sizeof(from));
            memset(&msg, 0, sizeof(msg));
            iov.iov_base = &byte;
            iov.iov_len = 1;
            msg.msg_name = &from;
            msg.msg_namelen = sizeof(from);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            if (sendto(sfd, &byte, 1, 0, (struct sockaddr *) &sa, sizeof(sa)) !=
                1) {
                FAIL("sendto");
            } else if (recvmsg(rfd, &msg, 0) != 1) {
                FAIL("recvmsg");
            } else {
                unsigned want =
                    (unsigned) (offsetof(struct sockaddr_un, sun_path) +
                                strlen(sender) + 1);
                EXPECT_TRUE(
                    (unsigned) msg.msg_namelen == want &&
                        !strncmp(from.sun_path, sender, sizeof(from.sun_path)),
                    "namelen or bytes describe the host spelling");
                if ((unsigned) msg.msg_namelen != want)
                    fprintf(stderr, "  namelen %u, want %u\n",
                            (unsigned) msg.msg_namelen, want);
            }
        }
        if (rfd >= 0)
            close(rfd);
        if (sfd >= 0)
            close(sfd);
    }

    /* A Linux-legal guest name whose translated host spelling overflows the
     * 104-byte macOS sun_path: the escape more than doubles a mixed-case
     * component and the sysroot prefix comes on top, so this is the common
     * case for deep socket paths, not a corner.
     */
    TEST("a name whose host spelling overflows macOS sun_path still binds");
    {
        int lfd4, c4;

        snprintf(path, sizeof(path),
                 "%s/Very.Long.Mixed.Case.Directory.For.Escapes", DIR_S);
        if (mkdir(path, 0755) != 0 && errno != EEXIST) {
            FAIL("mkdir");
        } else {
            snprintf(path, sizeof(path),
                     "%s/Very.Long.Mixed.Case.Directory.For.Escapes/S.sock",
                     DIR_S);
            lfd4 = unix_bind(path, SOCK_STREAM, 4);
            if (lfd4 < 0) {
                FAIL("bind");
            } else {
                TEST("  and connect through it round-trips");
                c4 = connect_send(path, 'x');
                EXPECT_TRUE(c4 >= 0 && accept_token(lfd4) == 'x',
                            "connect + read");
                if (c4 >= 0)
                    close(c4);
                close(lfd4);
            }
        }
    }

    /* A socket address is a path, so it inherits the /dev/shm never-follow
     * rule. bind(2) and connect(2) take a sockaddr rather than a dirfd and
     * at_flags, so that rule cannot ride on an open flag here and is checked
     * outright. Following a guest-planted link reported ENOTSOCK for a host
     * file that exists and ENOENT for one that does not, which tells the guest
     * whether any host path exists, including every path
     * is_guest_system_path() keeps it from naming: connecting to /etc/passwd
     * directly is ENOENT, and through the link it was not.
     */
    TEST("connect does not follow a shm symlink out of the backing dir");
    {
        unlink("/dev/shm/absock-escape");
        if (symlink("/etc/passwd", "/dev/shm/absock-escape") != 0) {
            FAIL("symlink into /dev/shm");
        } else {
            int sfd2 = socket(AF_UNIX, SOCK_STREAM, 0);

            memset(&sa, 0, sizeof(sa));
            sa.sun_family = AF_UNIX;
            snprintf(sa.sun_path, sizeof(sa.sun_path), "%s",
                     "/dev/shm/absock-escape");
            errno = 0;
            EXPECT_ERRNO(connect(sfd2, (struct sockaddr *) &sa, sizeof(sa)),
                         ELOOP, "should refuse to follow the link");
            if (sfd2 >= 0)
                close(sfd2);
            unlink("/dev/shm/absock-escape");
        }
    }

    /* The same rule for bind, which is the half that writes: a dangling link
     * binds the socket at its target, so following one plants a socket file
     * anywhere the guest can name as a target. The recipe checks host-side
     * that nothing landed there.
     */
    TEST("bind does not follow a shm symlink out of the backing dir");
    {
        unlink("/dev/shm/absock-bind-escape");
        if (symlink("/tmp/elfuse-absock-escapee",
                    "/dev/shm/absock-bind-escape") != 0) {
            FAIL("symlink into /dev/shm");
        } else {
            int sfd3 = socket(AF_UNIX, SOCK_STREAM, 0);

            memset(&sa, 0, sizeof(sa));
            sa.sun_family = AF_UNIX;
            snprintf(sa.sun_path, sizeof(sa.sun_path), "%s",
                     "/dev/shm/absock-bind-escape");
            errno = 0;
            EXPECT_ERRNO(bind(sfd3, (struct sockaddr *) &sa, sizeof(sa)), ELOOP,
                         "should refuse to follow the link");
            if (sfd3 >= 0)
                close(sfd3);
            unlink("/dev/shm/absock-bind-escape");
        }
    }

    /* An over-length name is reached through a link in a namespace directory,
     * and reading the address back has to undo it. fork is posix_spawn plus a
     * state handshake, so the child is a fresh elfuse process: it inherits the
     * namespace id but has not created that directory itself. Undoing the link
     * used to be conditional on having created it, so a guest that only
     * inherited the socket read back the /tmp link path in place of the name
     * it asked for, and could neither stat nor rebind what it was told.
     */
    TEST("a forked child reads back the guest spelling, not the link");
    {
        int lfd5;
        pid_t pid;

        snprintf(path, sizeof(path),
                 "%s/Very.Long.Mixed.Case.Directory.For.Escapes/F.sock", DIR_S);
        lfd5 = unix_bind(path, SOCK_STREAM, 4);
        if (lfd5 < 0) {
            FAIL("bind");
        } else {
            pid = fork();
            if (pid == 0) {
                struct sockaddr_un csa;
                socklen_t clen = sizeof(csa);

                memset(&csa, 0, sizeof(csa));
                if (getsockname(lfd5, (struct sockaddr *) &csa, &clen) != 0)
                    _exit(2);
                _exit(strncmp(csa.sun_path, path, sizeof(csa.sun_path)) ? 1
                                                                        : 0);
            }
            if (pid < 0) {
                FAIL("fork");
            } else {
                int status = 0;

                waitpid(pid, &status, 0);
                EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                            "child read back the namespace link path");
            }
            close(lfd5);
        }
    }

    /* The socket is an ordinary directory entry to every other syscall. */
    TEST("unlink removes the socket by its guest name");
    snprintf(path, sizeof(path), "%s/My.Sock", DIR_S);
    EXPECT_TRUE(unlink(path) == 0 && stat(path, &st) != 0 && errno == ENOENT,
                "unlink + stat");
    if (lfd >= 0)
        close(lfd);

    SUMMARY("test-sysroot-absock-names");
    return fails > 0 ? 1 : 0;
}
