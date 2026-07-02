/*
 * test-shim-data-el1.c -- guest EL0 cannot read or write shim_data.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The shim_data block holds the identity cache, attention flag, urandom bitmap,
 * ring, and lock. Mapping it with AP[2:1]=00 (privileged-only) prevents a guest
 * from spoofing its own identity by storing directly to the cache GVA, or from
 * observing the bytes the urandom fast path will hand out next.
 *
 * This test:
 *   1. Parses /proc/self/maps to find [shim-data].
 *   2. Verifies the permission string is "---p" (PROT_NONE).
 *   3. Installs SIGSEGV handler + sigsetjmp; loads the first byte
 *      from the [shim-data] base; expects SIGSEGV.
 *   4. Same with a store; expects SIGSEGV.
 *   5. Verifies the identity and urandom fast paths still work
 *      AFTER the EL0 access attempts (no shim corruption).
 *   6. execve's self with argv[1]='post-exec' and reruns the perms
 *      and fault checks against the new image. Catches the
 *      regression where the execve mapping path forgets to apply
 *      EL1-only and silently downgrades shim_data to plain RW.
 */

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static sigjmp_buf segv_jmp;

static void on_sigsegv(int sig)
{
    (void) sig;
    siglongjmp(segv_jmp, 1);
}

static uint64_t find_shim_data_base(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return 0;
    char line[512];
    uint64_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "[shim-data]")) {
            unsigned long long lo = 0;
            char perms[8] = {0};
            if (sscanf(line, "%llx-%*llx %7s", &lo, perms) == 2) {
                printf("[shim-data] base=0x%llx perms=%s\n", lo, perms);
                if (strcmp(perms, "---p") != 0) {
                    fprintf(stderr,
                            "FAIL: [shim-data] perms %s, expected ---p\n",
                            perms);
                    fclose(fp);
                    return 0;
                }
                base = lo;
            }
            break;
        }
    }
    fclose(fp);
    return base;
}

static int probe_read(uint64_t addr)
{
    if (sigsetjmp(segv_jmp, 1) != 0)
        return -1; /* SIGSEGV caught */
    volatile uint8_t *p = (volatile uint8_t *) (uintptr_t) addr;
    volatile uint8_t v = *p;
    (void) v;
    return 0;
}

static int probe_write(uint64_t addr)
{
    if (sigsetjmp(segv_jmp, 1) != 0)
        return -1;
    volatile uint8_t *p = (volatile uint8_t *) (uintptr_t) addr;
    *p = 0xA5;
    return 0;
}

/* Phase 2 (post-execve): only the perm-string and fault checks. The identity
 * and urandom sanity is already exercised in phase 1; here the goal is to catch
 * a regression where execve maps shim_data with plain RW instead of
 * RW_EL1_ONLY.
 */
static int run_post_exec_checks(void)
{
    uint64_t base = find_shim_data_base();
    if (!base) {
        fprintf(stderr, "FAIL post-exec: shim-data missing or wrong perms\n");
        return 1;
    }
    struct sigaction sa = {0};
    sa.sa_handler = on_sigsegv;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    if (probe_read(base) != -1) {
        fprintf(stderr,
                "FAIL post-exec: read at 0x%llx did not fault "
                "(execve mapped shim_data RW instead of RW_EL1_ONLY)\n",
                (unsigned long long) base);
        return 1;
    }
    if (probe_write(base) != -1) {
        fprintf(stderr, "FAIL post-exec: write at 0x%llx did not fault\n",
                (unsigned long long) base);
        return 1;
    }
    printf("OK post-exec [shim-data] still EL1-only\n");
    printf("OK\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "post-exec") == 0)
        return run_post_exec_checks();

    uint64_t base = find_shim_data_base();
    if (!base)
        return 1;

    struct sigaction sa = {0};
    sa.sa_handler = on_sigsegv;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    /* Read of [shim-data] must fault. */
    if (probe_read(base) != -1) {
        fprintf(stderr, "FAIL: read at 0x%llx did not fault\n",
                (unsigned long long) base);
        return 1;
    }
    printf("OK read fault at base\n");

    /* Read further into the region (urandom ring area, offset 0x100). */
    if (probe_read(base + 0x100) != -1) {
        fprintf(stderr, "FAIL: read at 0x%llx did not fault\n",
                (unsigned long long) (base + 0x100));
        return 1;
    }
    printf("OK read fault at base+0x100\n");

    /* Store attempt must fault too. */
    if (probe_write(base) != -1) {
        fprintf(stderr, "FAIL: write at 0x%llx did not fault\n",
                (unsigned long long) base);
        return 1;
    }
    printf("OK write fault at base\n");

    /* After the fault attempts, identity fast path must still work. */
    register long x0 __asm__("x0");
    register long x8 __asm__("x8") = 172; /* getpid */
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory", "cc");
    if (x0 != getpid()) {
        fprintf(stderr,
                "FAIL: identity fast path broken after faults: "
                "raw getpid=%ld libc=%d\n",
                x0, getpid());
        return 1;
    }
    printf("OK identity fast path still works (pid=%ld)\n", x0);

    /* Urandom fast path too. */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/urandom");
        return 1;
    }
    char b;
    if (read(fd, &b, 1) != 1) {
        fprintf(stderr, "FAIL: urandom read broken after faults\n");
        return 1;
    }
    printf("OK urandom fast path still works\n");

    /* The host syscall handlers must also refuse to act on a guest-supplied
     * [shim-data] GVA. Without this defense, a guest could spoof the identity
     * cache via read(fd, shim_data_gva, n) instead of a direct EL0 store. The
     * host's gva_translate_perm rejects EL1-only descriptors before any
     * host_base+offset write fires; the syscall returns EFAULT.
     */
    errno = 0;
    ssize_t rc = read(fd, (void *) (uintptr_t) base, 1);
    if (rc != -1 || errno != EFAULT) {
        fprintf(stderr,
                "FAIL: read(fd, [shim-data], 1) = %zd errno=%d "
                "(expected -1/EFAULT, attacker could have spoofed cache)\n",
                rc, errno);
        close(fd);
        return 1;
    }
    printf("OK host-side spoofing attempt via read returned EFAULT\n");
    close(fd);

    /* Phase 2: re-exec self with argv[1]='post-exec' so the post-execve
     * shim_data mapping path is exercised. If exec.c forgets to use
     * RW_EL1_ONLY, the child process's [shim-data] perms come back as 'rw-p'
     * and the probe_read in run_post_exec_checks succeeds (no SIGSEGV), failing
     * the regression. The original child reaches argc=1 above; this path only
     * runs once.
     */
    char *exec_argv[] = {argv[0], "post-exec", NULL};
    execv("/proc/self/exe", exec_argv);
    perror("execv");
    return 1;
}
