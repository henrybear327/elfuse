/* Exercise the AF_NETLINK getsockname/sendto/recvfrom dispatch paths.
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression guard for the netlink socket emulation. Before getsockname,
 * sendto, and recvfrom were routed to the netlink handlers, these calls fell
 * through to the host socket syscalls on the underlying pipe fd and failed
 * with ENOTSOCK (errno 88), which in turn broke glibc getifaddrs(). The test
 * drives each of the three syscalls directly against a NETLINK_ROUTE socket
 * and then validates the end-to-end getifaddrs() path that originally
 * regressed.
 *
 * The assertions hold for both the elfuse emulation and a real Linux kernel
 * (the test matrix runs the same binary under qemu-aarch64), so only
 * implementation-independent netlink semantics are checked.
 */

#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static int pass, fail;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (cond) {                                                            \
            printf("PASS: %s\n", (msg));                                       \
            pass++;                                                            \
        } else {                                                               \
            printf("FAIL: %s (errno=%d %s)\n", (msg), errno, strerror(errno)); \
            fail++;                                                            \
        }                                                                      \
    } while (0)

/* RTM_GETLINK dump request: nlmsghdr immediately followed by ifinfomsg. */
struct getlink_req {
    struct nlmsghdr nlh;
    struct ifinfomsg ifi;
};

int main(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        printf("FAIL: socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE): %s\n",
               strerror(errno));
        /* Without a socket none of the dispatch paths can be reached. */
        printf("\n%d passed, %d failed\n", pass, fail + 1);
        return 1;
    }
    printf("PASS: socket(AF_NETLINK, NETLINK_ROUTE) = %d\n", fd);
    pass++;

    /* bind() with nl_pid=0 lets the kernel/emulation assign a port id. */
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    CHECK(bind(fd, (struct sockaddr *) &local, sizeof(local)) == 0,
          "bind(AF_NETLINK)");

    /* 1. getsockname(): previously ENOTSOCK on the pipe fd. */
    struct sockaddr_nl got = {0};
    socklen_t gotlen = sizeof(got);
    int rc = getsockname(fd, (struct sockaddr *) &got, &gotlen);
    CHECK(rc == 0 && gotlen >= sizeof(struct sockaddr_nl) &&
              got.nl_family == AF_NETLINK,
          "getsockname() returns an AF_NETLINK address");
    CHECK(rc == 0 && got.nl_pid != 0,
          "getsockname() reports a non-zero port id");

    /* 2. sendto(): flat request buffer, no msghdr. */
    struct getlink_req req = {0};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.ifi.ifi_family = AF_UNSPEC;

    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    ssize_t sent = sendto(fd, &req, req.nlh.nlmsg_len, 0,
                          (struct sockaddr *) &kernel, sizeof(kernel));
    CHECK(sent == (ssize_t) req.nlh.nlmsg_len,
          "sendto(RTM_GETLINK) accepts the request");

    /* 3. recvfrom(): drain the dump, expecting RTM_NEWLINK then NLMSG_DONE. */
    int saw_newlink = 0, saw_done = 0, src_ok = 0;
    for (int iter = 0; iter < 64 && !saw_done; iter++) {
        char buf[8192];
        struct sockaddr_nl src = {0};
        socklen_t srclen = sizeof(src);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) &src,
                             &srclen);
        if (n <= 0)
            break;
        if (srclen >= sizeof(struct sockaddr_nl) && src.nl_family == AF_NETLINK)
            src_ok = 1;
        for (struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
             NLMSG_OK(nlh, (unsigned) n); nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_type == RTM_NEWLINK)
                saw_newlink = 1;
            else if (nlh->nlmsg_type == NLMSG_DONE)
                saw_done = 1;
            else if (nlh->nlmsg_type == NLMSG_ERROR)
                saw_done = 1; /* stop draining on error terminator */
        }
    }
    CHECK(saw_newlink, "recvfrom() returns at least one RTM_NEWLINK");
    CHECK(src_ok, "recvfrom() fills an AF_NETLINK source address");

    close(fd);

    /* 4. End-to-end: glibc getifaddrs() drives getsockname + sendto + recv
     * internally. This is the exact call that regressed with ENOTSOCK.
     */
    struct ifaddrs *ifa = NULL;
    rc = getifaddrs(&ifa);
    CHECK(rc == 0, "getifaddrs() succeeds");
    int n_ifaces = 0;
    for (struct ifaddrs *p = ifa; p; p = p->ifa_next)
        if (p->ifa_name && p->ifa_name[0])
            n_ifaces++;
    CHECK(rc == 0 && n_ifaces > 0,
          "getifaddrs() enumerates at least one interface");
    if (ifa)
        freeifaddrs(ifa);

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
