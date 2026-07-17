/*
 * Shared I/O helpers for the LTP guest-side helper binaries.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Both helpers are single-translation-unit static cross-builds, so the
 * helpers live here as static functions rather than a separate object.
 * publish_status_line() writes one complete line through an exclusive
 * tempfile, fsync, and rename, so a reader sees either nothing or the
 * whole line.
 */

#ifndef LTP_HELPERS_STATUS_IO_H
#define LTP_HELPERS_STATUS_IO_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

static ssize_t write_all(int fd, const void *buf, size_t len)
{
    const char *cursor = (const char *) buf;
    size_t left = len;

    while (left > 0) {
        ssize_t wrote = write(fd, cursor, left);
        if (wrote < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        cursor += wrote;
        left -= (size_t) wrote;
    }

    return (ssize_t) len;
}

static ssize_t read_full(int fd, void *buf, size_t len)
{
    char *cursor = (char *) buf;
    size_t got = 0;

    while (got < len) {
        ssize_t n = read(fd, cursor + got, len - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break;
        got += (size_t) n;
    }

    return (ssize_t) got;
}

static int publish_status_line(const char *path, const char *line, size_t len)
{
    char tmp_path[PATH_MAX];
    int fd;
    int printed;

    if (!path)
        return 0;

    printed = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    if (printed < 0 || (size_t) printed >= sizeof(tmp_path))
        return -1;

    fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
        return -1;

    if (write_all(fd, line, len) < 0 || fsync(fd) < 0) {
        int saved_errno = errno;
        close(fd);
        unlink(tmp_path);
        errno = saved_errno;
        return -1;
    }

    if (close(fd) < 0) {
        unlink(tmp_path);
        return -1;
    }

    if (rename(tmp_path, path) < 0) {
        unlink(tmp_path);
        return -1;
    }

    return 0;
}

#endif
