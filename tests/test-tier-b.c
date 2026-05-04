/* Tier B correctness and fidelity tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: fchmodat2, openat2 RESOLVE_*, O_PATH enforcement, madvise
 * parity, /proc/self/oom_score_adj, /proc/self/fdinfo, cpuinfo scaling.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* fchmodat2 (SYS 452). */

#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

static void test_fchmodat2_basic(void)
{
    TEST("fchmodat2 basic");
    char path[] = "/tmp/elfuse-test-fchmodat2-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    close(fd);
    /* fchmodat2(AT_FDCWD, path, 0644, 0) should work like fchmodat */
    long rc = syscall(SYS_fchmodat2, AT_FDCWD, path, 0644, 0);
    if (rc < 0) {
        FAIL("fchmodat2");
        unlink(path);
        return;
    }
    struct stat st;
    stat(path, &st);
    unlink(path);
    EXPECT_TRUE((st.st_mode & 0777) == 0644, "mode mismatch");
}

static void test_fchmodat2_symlink_nofollow(void)
{
    TEST("fchmodat2 AT_SYMLINK_NOFOLLOW");
    char target[] = "/tmp/elfuse-test-fchmodat2-target-XXXXXX";
    char linkpath[64];

    int fd = mkstemp(target);
    if (fd < 0) {
        FAIL("mkstemp target");
        return;
    }
    close(fd);
    /* Derive the symlink name from the unique target so we never call mktemp,
     * which is racy and triggers a linker warning on glibc.
     */
    snprintf(linkpath, sizeof(linkpath), "%s.lnk", target);

    if (symlink(target, linkpath) < 0) {
        FAIL("symlink");
        unlink(target);
        return;
    }

    /* AT_SYMLINK_NOFOLLOW must change the symlink's mode, not the target's. */
    long rc =
        syscall(SYS_fchmodat2, AT_FDCWD, linkpath, 0700, AT_SYMLINK_NOFOLLOW);
    if (rc < 0) {
        FAIL("fchmodat2 nofollow");
        goto out;
    }

    struct stat st_link, st_target;
    if (lstat(linkpath, &st_link) < 0) {
        FAIL("lstat link");
        goto out;
    }
    if (stat(target, &st_target) < 0) {
        FAIL("stat target");
        goto out;
    }

    EXPECT_TRUE((st_link.st_mode & 0777) == 0700, "link mode mismatch");
    EXPECT_TRUE((st_target.st_mode & 0777) == 0600, "target mode changed");

out:
    unlink(linkpath);
    unlink(target);
}

/* openat2 (SYS 437). */

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

struct open_how {
    unsigned long long flags, mode, resolve;
};

#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04

static void test_openat2_basic(void)
{
    TEST("openat2 basic open");
    struct open_how how = {.flags = O_RDONLY, .mode = 0, .resolve = 0};
    long fd = syscall(SYS_openat2, AT_FDCWD, "/dev/null", &how, sizeof(how));
    if (fd < 0) {
        FAIL("openat2");
        return;
    }
    close(fd);
    PASS();
}

static void test_openat2_resolve_beneath(void)
{
    TEST("openat2 RESOLVE_BENEATH rejects ..");
    /* Open a directory first */
    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /tmp");
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_BENEATH};
    long fd = syscall(SYS_openat2, dirfd, "../etc/passwd", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close(fd);
        FAIL("should have rejected .. traversal");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_beneath_allows_internal_dotdot(void)
{
    TEST("openat2 RESOLVE_BENEATH allows in-root ..");

    char dir_template[] = "/tmp/elfuse-openat2-beneath-XXXXXX";
    char subdir[PATH_MAX], target[PATH_MAX];
    int dirfd = -1, filefd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(subdir, sizeof(subdir), "%s/subdir", dir_template);
    snprintf(target, sizeof(target), "%s/file", dir_template);
    if (mkdir(subdir, 0700) < 0) {
        FAIL("mkdir");
        goto out;
    }

    filefd = open(target, O_CREAT | O_RDONLY, 0600);
    if (filefd < 0) {
        FAIL("open file");
        goto out;
    }
    close(filefd);
    filefd = -1;

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_BENEATH};
    long fd = syscall(SYS_openat2, dirfd, "subdir/../file", &how, sizeof(how));
    if (fd < 0) {
        FAIL("openat2");
        goto out;
    }
    close((int) fd);
    PASS();

out:
    if (dirfd >= 0)
        close(dirfd);
    if (filefd >= 0)
        close(filefd);
    unlink(target);
    rmdir(subdir);
    rmdir(dir_template);
}

static void test_openat2_resolve_in_root_clamps_dotdot(void)
{
    TEST("openat2 RESOLVE_IN_ROOT clamps .. at root");

    char dir_template[] = "/tmp/elfuse-openat2-inroot-XXXXXX";
    char target[PATH_MAX];
    int dirfd = -1, filefd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(target, sizeof(target), "%s/file", dir_template);
    filefd = open(target, O_CREAT | O_RDONLY, 0600);
    if (filefd < 0) {
        FAIL("open file");
        goto out;
    }
    close(filefd);
    filefd = -1;

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_IN_ROOT};
    long fd = syscall(SYS_openat2, dirfd, "/../file", &how, sizeof(how));
    if (fd < 0) {
        FAIL("openat2");
        goto out;
    }
    close((int) fd);
    PASS();

out:
    if (dirfd >= 0)
        close(dirfd);
    if (filefd >= 0)
        close(filefd);
    unlink(target);
    rmdir(dir_template);
}

static void test_openat2_resolve_no_symlinks_intermediate(void)
{
    TEST("openat2 RESOLVE_NO_SYMLINKS rejects intermediate symlink");

    char dir_template[] = "/tmp/elfuse-openat2-XXXXXX";
    char target_dir[PATH_MAX], subfile[PATH_MAX];
    char link_path[PATH_MAX];
    int dirfd = -1, filefd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(target_dir, sizeof(target_dir), "%s/real", dir_template);
    snprintf(subfile, sizeof(subfile), "%s/subfile", target_dir);
    snprintf(link_path, sizeof(link_path), "%s/link", dir_template);

    if (mkdir(target_dir, 0700) < 0) {
        FAIL("mkdir");
        goto out;
    }
    filefd = open(subfile, O_CREAT | O_RDWR, 0600);
    if (filefd < 0) {
        FAIL("open subfile");
        goto out;
    }
    close(filefd);
    filefd = -1;
    if (symlink("real", link_path) < 0) {
        FAIL("symlink");
        goto out;
    }

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_SYMLINKS};
    long fd = syscall(SYS_openat2, dirfd, "link/subfile", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected ELOOP");
        goto out;
    }
    EXPECT_TRUE(errno == ELOOP, "wrong errno");

out:
    if (dirfd >= 0)
        close(dirfd);
    if (filefd >= 0)
        close(filefd);
    unlink(link_path);
    unlink(subfile);
    rmdir(target_dir);
    rmdir(dir_template);
}

static void test_openat2_resolve_beneath_rejects_symlink_escape(void)
{
    TEST("openat2 RESOLVE_BENEATH rejects symlink escape");

    char dir_template[] = "/tmp/elfuse-openat2-escape-XXXXXX";
    char link_path[PATH_MAX];
    int dirfd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(link_path, sizeof(link_path), "%s/link", dir_template);
    if (symlink("/etc", link_path) < 0) {
        FAIL("symlink");
        goto out;
    }

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_BENEATH};
    long fd = syscall(SYS_openat2, dirfd, "link/passwd", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV");
        goto out;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");

out:
    if (dirfd >= 0)
        close(dirfd);
    unlink(link_path);
    rmdir(dir_template);
}

static void test_openat2_resolve_no_magiclinks_proc_fd(void)
{
    TEST("openat2 RESOLVE_NO_MAGICLINKS rejects /proc/self/fd");
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_MAGICLINKS};
    long fd =
        syscall(SYS_openat2, AT_FDCWD, "/proc/self/fd/0", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected ELOOP");
        return;
    }
    EXPECT_TRUE(errno == ELOOP, "wrong errno");
}

static void test_openat2_resolve_no_magiclinks_proc_cwd(void)
{
    TEST("openat2 RESOLVE_NO_MAGICLINKS rejects proc cwd magiclinks");
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_MAGICLINKS};
    char cwd[256];

    if (!getcwd(cwd, sizeof(cwd))) {
        FAIL("getcwd");
        return;
    }
    if (chdir("/proc") < 0) {
        FAIL("chdir");
        return;
    }

    errno = 0;
    long fd = syscall(SYS_openat2, AT_FDCWD, "self/fd/0", &how, sizeof(how));
    int saved_errno = errno;
    if (chdir(cwd) < 0) {
        FAIL("restore cwd");
        return;
    }

    errno = saved_errno;
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected ELOOP");
        return;
    }
    EXPECT_TRUE(errno == ELOOP, "wrong errno");
}

/* O_PATH enforcement. */

#ifndef O_PATH
#define O_PATH 010000000
#endif

#ifndef MADV_COLD
#define MADV_COLD 20
#endif

static void test_opath_read_fails(void)
{
    TEST("O_PATH fd rejects read");
    int fd = open("/dev/null", O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    char buf[1];
    ssize_t n = read(fd, buf, 1);
    close(fd);
    EXPECT_TRUE(n < 0 && errno == EBADF, "read should return EBADF");
}

static void test_opath_write_fails(void)
{
    TEST("O_PATH fd rejects write");
    int fd = open("/dev/null", O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    ssize_t n = write(fd, "x", 1);
    close(fd);
    EXPECT_TRUE(n < 0 && errno == EBADF, "write should return EBADF");
}

static void test_opath_fstat_works(void)
{
    TEST("O_PATH fd allows fstat");
    int fd = open("/dev/null", O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    struct stat st;
    int rc = fstat(fd, &st);
    close(fd);
    EXPECT_TRUE(rc == 0, "fstat should work on O_PATH");
}

/* madvise parity. */

static void test_madvise_cold(void)
{
    TEST("madvise MADV_COLD accepted");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    int rc = madvise(p, 4096, MADV_COLD);
    munmap(p, 4096);
    EXPECT_TRUE(rc == 0, "madvise MADV_COLD");
}

static void test_madvise_dontneed_unmapped(void)
{
    TEST("madvise DONTNEED on unmapped returns ENOMEM");
    /* Map a page, then unmap the second half to create a hole */
    void *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    munmap((char *) p + 4096, 4096);
    /* MADV_DONTNEED across the boundary should fail */
    int rc = madvise(p, 8192, MADV_DONTNEED);
    munmap(p, 4096);
    EXPECT_TRUE(rc < 0 && errno == ENOMEM, "expected ENOMEM for unmapped hole");
}

/* /proc paths. */

static void test_proc_oom_score_adj(void)
{
    TEST("/proc/self/oom_score_adj readable");
    int fd = open("/proc/self/oom_score_adj", O_RDONLY);
    if (fd < 0) {
        FAIL("open");
        return;
    }
    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
        buf[n] = '\0';
        int val = atoi(buf);
        EXPECT_TRUE(val == 0, "unexpected value");
    } else {
        FAIL("read");
    }
}

static void test_proc_oom_score_adj_persists_write(void)
{
    TEST("/proc/self/oom_score_adj write persists");
    int fd = open("/proc/self/oom_score_adj", O_RDWR);
    if (fd < 0) {
        FAIL("open");
        return;
    }

    const char value[] = "123\n";
    if (write(fd, value, sizeof(value) - 1) != (ssize_t) (sizeof(value) - 1)) {
        close(fd);
        FAIL("write");
        return;
    }
    close(fd);

    fd = open("/proc/self/oom_score_adj", O_RDONLY);
    if (fd < 0) {
        FAIL("reopen");
        return;
    }

    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        FAIL("read");
        return;
    }

    buf[n] = '\0';
    EXPECT_TRUE(atoi(buf) == 123, "value did not persist");
}

static void test_signalfd_efault_preserves_pending(void)
{
    TEST("signalfd EFAULT preserves pending signal");

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    int fd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (fd < 0) {
        FAIL("signalfd");
        return;
    }

    kill(getpid(), SIGUSR1);
    errno = 0;
    /* Deliberately bad pointer to verify the kernel reports EFAULT. */
    ssize_t bad = syscall(SYS_read, fd,
                          /* cppcheck-suppress intToPointerCast */
                          (void *) 1, sizeof(struct signalfd_siginfo));
    if (bad != -1 || errno != EFAULT) {
        close(fd);
        FAIL("expected EFAULT");
        return;
    }

    struct signalfd_siginfo info;
    memset(&info, 0, sizeof(info));
    ssize_t good = read(fd, &info, sizeof(info));
    close(fd);
    if (good == (ssize_t) sizeof(info) &&
        info.ssi_signo == (uint32_t) SIGUSR1) {
        PASS();
    } else {
        FAIL("signal was lost after EFAULT");
    }
}

static void test_proc_fdinfo(void)
{
    TEST("/proc/self/fdinfo/0 readable");
    int fd = open("/proc/self/fdinfo/0", O_RDONLY);
    if (fd < 0) {
        FAIL("open");
        return;
    }
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
        buf[n] = '\0';
        EXPECT_TRUE(strstr(buf, "pos:") && strstr(buf, "flags:"),
                    "missing pos/flags fields");
    } else {
        FAIL("read");
    }
}

static void test_proc_cpuinfo_all_cpus(void)
{
    TEST("/proc/cpuinfo lists all CPUs");
    int fd = open("/proc/cpuinfo", O_RDONLY);
    if (fd < 0) {
        FAIL("open");
        return;
    }
    char buf[65536];
    ssize_t total = 0;
    for (;;) {
        ssize_t n = read(fd, buf + total, sizeof(buf) - total - 1);
        if (n <= 0)
            break;
        total += n;
    }
    close(fd);
    buf[total] = '\0';

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    int count = 0;
    char *p = buf;
    while ((p = strstr(p, "processor\t:"))) {
        count++;
        p++;
    }
    if (count == ncpu)
        PASS();
    else {
        printf("FAIL: found %d cpus, expected %ld\n", count, ncpu);
        fails++;
    }
}

int main(void)
{
    printf("Tier B correctness tests:\n");

    /* fchmodat2 */
    test_fchmodat2_basic();
    test_fchmodat2_symlink_nofollow();

    /* openat2 RESOLVE_* */
    test_openat2_basic();
    test_openat2_resolve_beneath();
    test_openat2_resolve_beneath_allows_internal_dotdot();
    test_openat2_resolve_in_root_clamps_dotdot();
    test_openat2_resolve_no_symlinks_intermediate();
    test_openat2_resolve_beneath_rejects_symlink_escape();
    test_openat2_resolve_no_magiclinks_proc_fd();
    test_openat2_resolve_no_magiclinks_proc_cwd();

    /* O_PATH */
    test_opath_read_fails();
    test_opath_write_fails();
    test_opath_fstat_works();

    /* madvise */
    test_madvise_cold();
    test_madvise_dontneed_unmapped();

    /* /proc */
    test_proc_oom_score_adj();
    test_proc_oom_score_adj_persists_write();
    test_proc_fdinfo();
    test_proc_cpuinfo_all_cpus();

    /* signalfd */
    test_signalfd_efault_preserves_pending();

    SUMMARY("test-tier-b");
    return fails ? 1 : 0;
}
