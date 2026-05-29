/* test-shim-verbose-trace.c -- fixture for verbose tracing of shim fast paths
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include "raw-syscall.h"

#ifndef __NR_openat
#define __NR_openat 56
#endif
#ifndef __NR_close
#define __NR_close 57
#endif
#ifndef __NR_read
#define __NR_read 63
#endif
#ifndef __NR_getpid
#define __NR_getpid 172
#endif

#define AT_FDCWD -100

int main(void)
{
    long pid = raw_syscall0(__NR_getpid);
    if (pid <= 0) {
        fprintf(stderr, "getpid failed: %ld\n", pid);
        return 1;
    }

    long fd = raw_syscall4(__NR_openat, AT_FDCWD, (long) "/dev/urandom", 0, 0);
    if (fd < 0) {
        fprintf(stderr, "openat /dev/urandom failed: %ld\n", fd);
        return 1;
    }

    unsigned char byte = 0;
    long n = raw_syscall3(__NR_read, fd, (long) &byte, 1);
    long close_rc = raw_syscall1(__NR_close, fd);
    if (n != 1 || close_rc < 0) {
        fprintf(stderr, "read/close failed: n=%ld close=%ld\n", n, close_rc);
        return 1;
    }

    printf("pid=%ld byte=%u\n", pid, (unsigned) byte);
    return 0;
}
