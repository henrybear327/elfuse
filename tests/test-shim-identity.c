/* test-shim-identity.c -- verify identity syscalls do not trust vDSO memory
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A guest can legally unmap or replace its vDSO page. getpid/getppid/getuid/
 * geteuid/getgid/getegid must still be sourced from host-side process state,
 * not from guest-remappable vDSO contents.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "raw-syscall.h"

#ifndef __NR_getpid
#define __NR_getpid 172
#endif
#ifndef __NR_getppid
#define __NR_getppid 173
#endif
#ifndef __NR_getuid
#define __NR_getuid 174
#endif
#ifndef __NR_geteuid
#define __NR_geteuid 175
#endif
#ifndef __NR_getgid
#define __NR_getgid 176
#endif
#ifndef __NR_getegid
#define __NR_getegid 177
#endif
#ifndef __NR_mmap
#define __NR_mmap 222
#endif

#define VDSO_BASE ((void *) (uintptr_t) 0x0000F000UL)
#define VDSO_SIZE 0x1000UL

static int failures = 0;

#define EXPECT_EQ_LONG(a_expr, b_expr, label)                        \
    do {                                                             \
        long _a = (long) (a_expr);                                   \
        long _b = (long) (b_expr);                                   \
        if (_a != _b) {                                              \
            fprintf(stderr, "FAIL %s: %ld != %ld\n", label, _a, _b); \
            failures++;                                              \
        }                                                            \
    } while (0)

static long parse_status_field(const char *key)
{
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp)
        return -1;
    char line[256];
    long value = -1;
    size_t klen = strlen(key);
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, key, klen) == 0 && line[klen] == ':') {
            value = strtol(line + klen + 1, NULL, 10);
            break;
        }
    }
    fclose(fp);
    return value;
}

static void check_self(const char *phase)
{
    long pid = raw_syscall0(__NR_getpid);
    long ppid = raw_syscall0(__NR_getppid);
    long uid = raw_syscall0(__NR_getuid);
    long euid = raw_syscall0(__NR_geteuid);
    long gid = raw_syscall0(__NR_getgid);
    long egid = raw_syscall0(__NR_getegid);

    EXPECT_EQ_LONG(pid, parse_status_field("Pid"), "getpid vs /proc");
    EXPECT_EQ_LONG(ppid, parse_status_field("PPid"), "getppid vs /proc");

    /* Repeated calls must be stable. */
    EXPECT_EQ_LONG(pid, raw_syscall0(__NR_getpid), "getpid repeat");
    EXPECT_EQ_LONG(uid, raw_syscall0(__NR_getuid), "getuid repeat");
    EXPECT_EQ_LONG(euid, raw_syscall0(__NR_geteuid), "geteuid repeat");
    EXPECT_EQ_LONG(gid, raw_syscall0(__NR_getgid), "getgid repeat");
    EXPECT_EQ_LONG(egid, raw_syscall0(__NR_getegid), "getegid repeat");

    printf("%s: pid=%ld ppid=%ld uid=%ld euid=%ld gid=%ld egid=%ld\n", phase,
           pid, ppid, uid, euid, gid, egid);
}

static void remap_vdso_page(void)
{
    long p = raw_syscall6(__NR_mmap, (long) VDSO_BASE, VDSO_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p < 0) {
        fprintf(stderr, "FAIL mmap(MAP_FIXED vDSO): %s\n", strerror((int) -p));
        failures++;
        return;
    }
    if ((void *) (uintptr_t) p != VDSO_BASE) {
        fprintf(stderr, "FAIL mmap(MAP_FIXED vDSO): got %p\n",
                (void *) (uintptr_t) p);
        failures++;
        return;
    }

    memset(VDSO_BASE, 0xA5, VDSO_SIZE);
}

static void check_fork_child(void)
{
    long parent_pid = raw_syscall0(__NR_getpid);
    pid_t kid = fork();
    if (kid < 0) {
        fprintf(stderr, "FAIL fork: %s\n", strerror(errno));
        failures++;
        return;
    }
    if (kid == 0) {
        long child_pid = raw_syscall0(__NR_getpid);
        long child_ppid = raw_syscall0(__NR_getppid);
        if (child_pid == parent_pid) {
            fprintf(stderr,
                    "FAIL fork-child: getpid==parent_pid (stale vvar)\n");
            _exit(2);
        }
        if (child_ppid != parent_pid) {
            fprintf(stderr, "FAIL fork-child: getppid=%ld parent_pid=%ld\n",
                    child_ppid, parent_pid);
            _exit(3);
        }
        _exit(0);
    }
    int wstatus = 0;
    if (waitpid(kid, &wstatus, 0) != kid) {
        fprintf(stderr, "FAIL fork-child waitpid: %s\n", strerror(errno));
        failures++;
        return;
    }
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        fprintf(stderr, "FAIL fork-child exit status %d\n", wstatus);
        failures++;
    }
}

int main(void)
{
    printf("test-shim-identity: identity syscalls ignore remapped vDSO\n");
    check_self("before-remap");
    remap_vdso_page();
    check_self("after-remap");
    check_fork_child();
    if (failures) {
        fprintf(stderr, "FAIL: %d check(s) failed\n", failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
