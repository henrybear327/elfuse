/*
 * Shared test utilities
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include "linux-openat2.h"
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

/* Directory- and file-level helpers for tests that assert on names.
 *
 * These take a full path rather than a name plus a directory, so a test that
 * works in one place is not rewritten to work in another. Shared rather than
 * per-test because the filename suite turns on what these compare: a private
 * copy that checked a prefix where its siblings check the whole contents would
 * make two lanes disagree about what "the file reads back correctly" means.
 */
static inline int file_write(const char *path, const char *text)
{
    size_t len = strlen(text);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    int rc;

    if (fd < 0)
        return -1;
    rc = write_fd_all(fd, text, len);
    close(fd);
    return rc;
}

/* 0 when @path holds exactly @want, -1 otherwise or on any error. */
static inline int file_content_is(const char *path, const char *want)
{
    char buf[256];

    if (read_file_nul(path, buf, sizeof(buf)) < 0)
        return -1;
    return strcmp(buf, want) ? -1 : 0;
}

/* Dirfd-relative siblings of file_write and file_content_is, for lanes that
 * address fixtures through a descriptor rather than a full path.
 */
static inline int file_write_at(int dirfd, const char *name, const char *text)
{
    int fd = openat(dirfd, name, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    int rc;

    if (fd < 0)
        return -1;
    rc = write_fd_all(fd, text, strlen(text));
    close(fd);
    return rc;
}

static inline int file_content_at_is(int dirfd,
                                     const char *name,
                                     const char *want)
{
    char buf[256];
    int fd = openat(dirfd, name, O_RDONLY);
    ssize_t n;

    if (fd < 0)
        return -1;
    n = read_fd_all_nul(fd, buf, sizeof(buf));
    close(fd);
    if (n < 0)
        return -1;
    return strcmp(buf, want) ? -1 : 0;
}

/* 0 when @path begins with @want. For fixtures staged by a shell recipe, which
 * appends a newline that the assertion is not about.
 */
static inline int file_content_starts_with(const char *path, const char *want)
{
    char buf[256];

    if (read_file_nul(path, buf, sizeof(buf)) < 0)
        return -1;
    return strncmp(buf, want, strlen(want)) ? -1 : 0;
}

/* Entries in @dir excluding "." and "..", or -1 if it cannot be opened. */
static inline int dir_entry_count(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *de;
    int n = 0;

    if (!d)
        return -1;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, ".."))
            n++;
    }
    closedir(d);
    return n;
}

/* Membership only; an unopenable @dir reads as absent, so a negative-only
 * assertion must pair with a positive one or use dir_count_name, whose -1
 * keeps "cannot read" distinct from "not present".
 */
static inline bool dir_contains(const char *dir, const char *name)
{
    DIR *d = opendir(dir);
    struct dirent *de;
    bool found = false;

    if (!d)
        return false;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, name)) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

/* Occurrences of @name in @dir, or -1 if it cannot be opened. dir_contains
 * answers membership only; a collapse regression needs the count, because the
 * decoded spelling of one entry can equal the literal spelling of another.
 */
static inline int dir_count_name(const char *dir, const char *name)
{
    DIR *d = opendir(dir);
    struct dirent *de;
    int n = 0;

    if (!d)
        return -1;
    while ((de = readdir(d)))
        if (!strcmp(de->d_name, name))
            n++;
    closedir(d);
    return n;
}

/* Bind a pathname AF_UNIX socket of @type at @path, listening with @backlog
 * when it is positive. Returns the descriptor, or -1 with the socket closed
 * and no socket file created by this call left behind.
 * An over-long @path is truncated into sun_path exactly as the lanes did by
 * hand; the bind then addresses the truncated name, which the caller's own
 * assertions catch.
 */
static inline int unix_bind(const char *path, int type, int backlog)
{
    struct sockaddr_un sa;
    int fd = socket(AF_UNIX, type, 0);

    if (fd < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    if (backlog > 0 && listen(fd, backlog) != 0) {
        /* bind created the file, so a rerun would get EADDRINUSE from it.
         * Only this branch unlinks: on a bind failure the file is not this
         * call's, and removing it would break whoever owns it. sun_path,
         * not @path, because the file carries the truncated name.
         */
        unlink(sa.sun_path);
        close(fd);
        return -1;
    }
    return fd;
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
