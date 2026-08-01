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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "raw-syscall.h"

/* openat2(2) scaffolding for tests that drive the second walker directly.
 * Static libcs predate the syscall's wrapper and uapi header, so the number,
 * the struct, and the resolve bits have to be spelled out by hand; they live
 * here once so every test that needs them agrees on the ABI.
 */
#ifndef SYS_openat2
#define SYS_openat2 437
#endif

struct open_how {
    unsigned long long flags, mode, resolve;
};

#define RESOLVE_NO_XDEV 0x01
#define RESOLVE_NO_SYMLINKS 0x04

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

/* Read a file whose size is not available from st_size (for example a proc
 * file) until EOF, growing the buffer and appending a NUL terminator. */
static inline ssize_t read_file_dynamic_nul(const char *path, char **buf_out,
                                            size_t *len_out)
{
    if (!path || !buf_out || !len_out) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    size_t cap = 64 * 1024;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }

    for (;;) {
        if (len + 1 >= cap) {
            if (cap > SIZE_MAX / 2) {
                free(buf);
                close(fd);
                errno = EOVERFLOW;
                return -1;
            }
            size_t new_cap = cap * 2;
            char *new_buf = realloc(buf, new_cap);
            if (!new_buf) {
                free(buf);
                close(fd);
                errno = ENOMEM;
                return -1;
            }
            buf = new_buf;
            cap = new_cap;
        }

        ssize_t n = read(fd, buf + len, cap - len - 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        len += (size_t) n;
    }
    close(fd);

    buf[len] = '\0';
    *buf_out = buf;
    *len_out = len;
    return (ssize_t) len;
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
