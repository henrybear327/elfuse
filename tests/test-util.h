/*
 * Shared test utilities
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "raw-syscall.h"

static inline ssize_t read_fd_all_nul(int fd, char *buf, size_t bufsz)
{
    if (bufsz == 0)
        return -1;

    ssize_t total = 0;
    while ((size_t) total < bufsz - 1) {
        ssize_t n = read(fd, buf + total, bufsz - 1 - (size_t) total);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        total += n;
    }
    buf[total] = '\0';
    return total;
}

static inline ssize_t read_file_nul(const char *path, char *buf, size_t bufsz)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t total = read_fd_all_nul(fd, buf, bufsz);
    close(fd);
    return total;
}

static inline ssize_t raw_read_fd_all_nul(int fd, char *buf, size_t bufsz)
{
    if (bufsz == 0)
        return -1;

    ssize_t total = 0;
    while ((size_t) total < bufsz - 1) {
        long n = raw_syscall3(__NR_read, fd, (long) (buf + total),
                              (long) (bufsz - 1 - (size_t) total));
        if (n == -EINTR)
            continue;
        if (n <= 0)
            break;
        total += (ssize_t) n;
    }
    buf[total] = '\0';
    return total;
}

static inline int raw_open_rdonly(const char *path)
{
    return (int) raw_syscall4(__NR_openat, AT_FDCWD, (long) path, O_RDONLY, 0);
}

static inline int write_fd_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *) buf;
    size_t written = 0;

    while (written < len) {
        ssize_t n = write(fd, p + written, len - written);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        written += (size_t) n;
    }

    return 0;
}

/* Create (or truncate) path and write contents, retrying short writes. */
static inline int write_file(const char *path, const char *contents)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0)
        return -1;
    int rc = write_fd_all(fd, contents, strlen(contents));
    close(fd);
    return rc;
}

/* Copy src to dst as an executable (mode 0755), retrying short writes. Used by
 * the exec tests, which stage a copy of the running binary somewhere the
 * translation layer has to resolve.
 */
static inline int copy_file_exec(const char *src, const char *dst)
{
    int in = open(src, O_RDONLY);
    if (in < 0)
        return -1;
    int out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (out < 0) {
        close(in);
        return -1;
    }

    int rc = 0;
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0)
        if (write_fd_all(out, buf, (size_t) n) < 0) {
            rc = -1;
            break;
        }
    if (n < 0)
        rc = -1;
    close(in);
    close(out);
    return rc;
}

static inline void test_unreachable(void)
{
    abort();
#if defined(__GNUC__) || defined(__clang__)
    __builtin_unreachable();
#endif
}

static inline ssize_t raw_read_file_nul(const char *path,
                                        char *buf,
                                        size_t bufsz)
{
    int fd = raw_open_rdonly(path);
    if (fd < 0)
        return -1;

    ssize_t total = raw_read_fd_all_nul(fd, buf, bufsz);
    raw_syscall1(__NR_close, fd);
    return total;
}
