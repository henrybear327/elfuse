/*
 * test-mremap-tail-emfile exercises file-backed mremap bookkeeping while the
 * guest and host descriptor tables are exhausted.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This probe deliberately uses libc interfaces so it can serve as the
 * repository's portable C implementation of the regression.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif

static const size_t PAGE_SIZE = 4096;
static const size_t SPAN = 64 * 1024;
static const int FILL_LIMIT = 4096;

static void child_exit(int status)
{
    _exit(status);
}

static void child_fail(int status)
{
    child_exit(status);
}

static void child_probe(int file_fd, unsigned char *base)
{
    void *result = mremap(base, SPAN, 3 * SPAN, 0);
    if (result == MAP_FAILED || result != base)
        child_fail(10);

    base[SPAN] = 'T';
    base[2 * SPAN] = 'R';
    base[SPAN + PAGE_SIZE] = 'S';
    base[SPAN + 3 * PAGE_SIZE] = 'M';

    /* Exhaust both descriptor tables, then leave one slot available. */
    int last_dup = -1;
    int dup_error = 0;
    for (;;) {
        int duplicated = dup(file_fd);
        if (duplicated < 0) {
            dup_error = errno;
            break;
        }
        last_dup = duplicated;
    }
    if (dup_error != EMFILE || last_dup < 0)
        child_fail(11);
    if (close(last_dup) != 0)
        child_fail(12);

    /* Fill the region table with one-page file mappings separated by holes. */
    const size_t filler_length = (size_t) FILL_LIMIT * 2 * PAGE_SIZE;
    void *reserved = mmap(NULL, filler_length, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserved == MAP_FAILED)
        child_fail(13);
    if (munmap(reserved, filler_length) != 0)
        child_fail(13);

    void *last_filler = MAP_FAILED;
    int filler_count = 0;
    for (; filler_count < FILL_LIMIT; filler_count++) {
        void *address = (char *) reserved +
                        (size_t) filler_count * 2 * PAGE_SIZE;
        void *filler = mmap(address, PAGE_SIZE, PROT_NONE,
                            MAP_PRIVATE | MAP_FIXED, file_fd, 0);
        if (filler == MAP_FAILED) {
            int filler_errno = errno;
            if (filler_errno != ENOMEM || filler_count == 0)
                child_fail(filler_errno == ENOMEM ? 16 : 14);
            break;
        }
        if (filler != address)
            child_fail(15);
        last_filler = filler;
    }
    if (filler_count == FILL_LIMIT || last_filler == MAP_FAILED)
        child_fail(16);
    if (munmap(last_filler, PAGE_SIZE) != 0)
        child_fail(17);

    /* Consume the one descriptor released by the last filler mapping. */
    int probe_fd = dup(file_fd);
    if (probe_fd < 0)
        child_fail(22);

    /* Splitting either boundary of the child-private tail must fail before
     * changing memory or PTEs when no descriptor is available. */
    errno = 0;
    result = mremap(base, SPAN + 2 * PAGE_SIZE, SPAN + PAGE_SIZE, 0);
    int remap_errno = errno;
    if (result != MAP_FAILED || remap_errno != ENOMEM ||
        base[SPAN + PAGE_SIZE] != 'S')
        child_fail(23);

    errno = 0;
    int munmap_result = munmap(base + SPAN + 3 * PAGE_SIZE, PAGE_SIZE);
    int munmap_errno = errno;
    if (munmap_result != -1 || munmap_errno != ENOMEM ||
        base[SPAN + 3 * PAGE_SIZE] != 'M')
        child_fail(25);

    if (close(probe_fd) != 0)
        child_fail(27);

    /* old_size ends inside the child-private tail. */
    errno = 0;
    result = mremap(base, SPAN + PAGE_SIZE, 2 * SPAN + PAGE_SIZE,
                    MREMAP_MAYMOVE);
    remap_errno = errno;

    /* Drop all duplicate guest slots, retaining the original file fd. */
    for (int fd = 0; fd < FILL_LIMIT; fd++) {
        if (fd != file_fd)
            (void) close(fd);
    }
    if (munmap(reserved, filler_length) != 0)
        child_fail(18);

    /* A successful move owns a target mapping; release it before msync. */
    if (result != MAP_FAILED) {
        if (munmap(result, 2 * SPAN + PAGE_SIZE) != 0)
            child_fail(21);
    } else if (remap_errno != ENOMEM) {
        child_fail(21);
    }

    if (msync(base + 2 * SPAN, SPAN, MS_SYNC) != 0)
        child_fail(19);

    unsigned char byte = 0;
    if (pread(file_fd, &byte, 1, 2 * SPAN) != 1 || byte != 'R')
        child_fail(20);

    child_exit(0);
}

static void test_file_backed_mremap_tail_emfile(void)
{
    TEST("MAP_SHARED mremap tail EMFILE preserves source");

    char path[] = "/tmp/elfuse-mremap-tail-emfile-XXXXXX";
    int file_fd = mkstemp(path);
    if (file_fd < 0) {
        FAIL("create temp file failed");
        return;
    }
    (void) unlink(path);

    const size_t file_length = 4 * SPAN;
    if (ftruncate(file_fd, (off_t) file_length) != 0) {
        FAIL("truncate temp file failed");
        close(file_fd);
        return;
    }

    const size_t reservation_length = file_length + PAGE_SIZE;
    void *reserved = mmap(NULL, reservation_length, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserved == MAP_FAILED || munmap(reserved, reservation_length) != 0) {
        FAIL("reserve source range failed");
        close(file_fd);
        return;
    }

    void *source_address = (char *) reserved + PAGE_SIZE;
    void *mapped = mmap(source_address, SPAN, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_FIXED, file_fd, 0);
    if (mapped == MAP_FAILED || mapped != source_address) {
        FAIL("map source file failed");
        close(file_fd);
        return;
    }

    unsigned char *base = mapped;
    base[0] = 'I';

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork failed");
        (void) munmap(base, SPAN);
        close(file_fd);
        return;
    }
    if (pid == 0)
        child_probe(file_fd, base);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        FAIL("wait failed");
    } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        char message[96];
        if (WIFEXITED(status))
            snprintf(message, sizeof(message), "child failed at step %d",
                     WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            snprintf(message, sizeof(message), "child killed by signal %d",
                     WTERMSIG(status));
        else
            snprintf(message, sizeof(message), "child ended unexpectedly");
        FAIL(message);
    } else {
        PASS();
    }

    (void) munmap(base, SPAN);
    close(file_fd);
}

int main(void)
{
    printf("test-mremap-tail-emfile: file-backed mremap atomicity\n");
    test_file_backed_mremap_tail_emfile();
    SUMMARY("test-mremap-tail-emfile");
    return fails != 0;
}
