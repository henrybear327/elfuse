/* MAP_SHARED msync tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: MAP_SHARED write-back to shm backing files.
 *
 * Syscalls exercised: shm_open/openat, ftruncate, mmap, msync, pread64
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* glibc 2.28 static: shm_open is broken (returns ENOSYS without trying).
 * Implement directly via openat on /dev/shm/.
 */
static int my_shm_open(const char *name, int oflag, int mode)
{
    char path[128];
    snprintf(path, sizeof(path), "/dev/shm%s", name);
    return open(path, oflag, mode);
}

static int my_shm_unlink(const char *name)
{
    char path[128];
    snprintf(path, sizeof(path), "/dev/shm%s", name);
    return unlink(path);
}

static void test_shared_msync_writes_file(void)
{
    TEST("MAP_SHARED msync writes backing file");

    char name[64];
    snprintf(name, sizeof(name), "/elfuse-msync-%ld", (long) getpid());
    int fd = my_shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        FAIL("shm_open failed");
        return;
    }
    my_shm_unlink(name);

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }

    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        close(fd);
        return;
    }

    const char msg[] = "elfuse-msync";
    memcpy(p, msg, sizeof(msg));

    if (msync(p, 4096, MS_SYNC) != 0) {
        FAIL("msync failed");
        munmap(p, 4096);
        close(fd);
        return;
    }

    char buf[sizeof(msg)] = {0};
    if (pread(fd, buf, sizeof(buf), 0) != (ssize_t) sizeof(buf)) {
        FAIL("pread failed");
    } else if (!memcmp(buf, msg, sizeof(msg))) {
        PASS();
    } else {
        FAIL("backing file did not receive MAP_SHARED writes");
    }

    munmap(p, 4096);
    close(fd);
}

static void test_shared_msync_refreshes_peer_mapping(void)
{
    TEST("MAP_SHARED msync refreshes peer mapping");

    char name[64];
    snprintf(name, sizeof(name), "/elfuse-msync-peer-%ld", (long) getpid());
    int fd = my_shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        FAIL("shm_open failed");
        return;
    }
    my_shm_unlink(name);

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }

    char *a = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char *b = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED || b == MAP_FAILED) {
        FAIL("mmap failed");
        if (a != MAP_FAILED)
            munmap(a, 4096);
        if (b != MAP_FAILED)
            munmap(b, 4096);
        close(fd);
        return;
    }

    a[128] = 'Q';
    if (msync(a, 4096, MS_SYNC) != 0) {
        FAIL("msync failed");
    } else if (b[128] == 'Q') {
        PASS();
    } else {
        FAIL("peer MAP_SHARED mapping did not observe write after msync");
    }

    munmap(a, 4096);
    munmap(b, 4096);
    close(fd);
}

static void test_shared_msync_preserves_alias_writes(void)
{
    TEST("MAP_SHARED msync preserves peer alias writes");

    char name[64];
    snprintf(name, sizeof(name), "/elfuse-msync-alias-%ld", (long) getpid());
    int fd = my_shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        FAIL("shm_open failed");
        return;
    }
    my_shm_unlink(name);

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }

    char *a = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char *b = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED || b == MAP_FAILED) {
        FAIL("mmap failed");
        if (a != MAP_FAILED)
            munmap(a, 4096);
        if (b != MAP_FAILED)
            munmap(b, 4096);
        close(fd);
        return;
    }

    a[0] = 'A';
    b[1] = 'B';

    if (msync(a, 4096, MS_SYNC) != 0) {
        FAIL("msync failed");
    } else {
        char buf[2] = {0};
        if (pread(fd, buf, sizeof(buf), 0) != (ssize_t) sizeof(buf))
            FAIL("pread failed");
        else if (buf[0] == 'A' && buf[1] == 'B' && a[1] == 'B')
            PASS();
        else
            FAIL("msync lost dirty bytes from peer alias");
    }

    munmap(a, 4096);
    munmap(b, 4096);
    close(fd);
}

static void test_shm_name_visible_after_fork(void)
{
    TEST("/dev/shm name visible after fork");

    char name[64];
    snprintf(name, sizeof(name), "/elfuse-msync-fork-%ld", (long) getpid());
    int fd = my_shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        FAIL("parent shm_open failed");
        return;
    }

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate failed");
        my_shm_unlink(name);
        close(fd);
        return;
    }

    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("parent mmap failed");
        my_shm_unlink(name);
        close(fd);
        return;
    }
    p[0] = 'P';
    msync(p, 4096, MS_SYNC);

    pid_t child = fork();
    if (child < 0) {
        FAIL("fork failed");
    } else if (child == 0) {
        int cfd = my_shm_open(name, O_RDWR, 0600);
        if (cfd < 0)
            _exit(2);
        char *cp = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, cfd, 0);
        if (cp == MAP_FAILED)
            _exit(3);
        int ok = cp[0] == 'P';
        if (ok) {
            cp[1] = 'C';
            ok = msync(cp, 4096, MS_SYNC) == 0;
        }
        _exit(ok ? 0 : 4);
    } else {
        int status;
        if (waitpid(child, &status, 0) < 0) {
            FAIL("waitpid failed");
        } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            FAIL("child could not reopen shared shm name");
        } else {
            char buf[2] = {0};
            if (pread(fd, buf, sizeof(buf), 0) != (ssize_t) sizeof(buf))
                FAIL("parent pread failed");
            else if (buf[1] == 'C')
                PASS();
            else
                FAIL("parent did not observe child shm write");
        }
    }

    munmap(p, 4096);
    close(fd);
    my_shm_unlink(name);
}

int main(void)
{
    printf("test-msync: MAP_SHARED msync tests\n\n");

    test_shared_msync_writes_file();
    test_shared_msync_refreshes_peer_mapping();
    test_shared_msync_preserves_alias_writes();
    test_shm_name_visible_after_fork();

    SUMMARY("test-msync");
    return fails ? 1 : 0;
}
