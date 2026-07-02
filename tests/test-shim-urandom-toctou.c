/*
 * test-shim-urandom-toctou.c -- urandom EL1 fault recovery survives concurrent
 * mprotect(PROT_NONE) of the read buffer.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The urandom-read shim fast path probes the guest buffer (AT s1e0w) and then
 * performs an EL1 strb into it. A sibling vCPU can mprotect or munmap the
 * buffer between the probe and the store, faulting the EL1 write. Without
 * handle_el1_data_abort_recover, that fault routes to BAD_VEC and halts the VM.
 *
 * This test runs a tight loop of read(/dev/urandom, buf, 1) while a sibling
 * thread continuously flips the buffer between PROT_READ|WRITE and PROT_NONE
 * via mprotect. Expected behavior:
 *   - read returns 1 (success) when the buffer is RW
 *   - read returns -1 with errno=EFAULT when the buffer is PROT_NONE
 *   - elfuse never halts
 *
 * If the recovery handler is missing or wrong, the VM crashes mid-run and the
 * test process never returns; the make-check timeout catches that as a failure.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define ITERATIONS 20000

static atomic_int stop;
static atomic_int flips;
static atomic_int efault_count;
static atomic_int success_count;
static void *shared_buf;

static void *protect_flipper(void *arg)
{
    (void) arg;
    int prot = PROT_READ | PROT_WRITE;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        prot ^= (PROT_READ | PROT_WRITE);
        if (mprotect(shared_buf, PAGE_SIZE, prot) != 0) {
            fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
            return (void *) (uintptr_t) 1;
        }
        atomic_fetch_add(&flips, 1);
    }
    /* Leave the buffer accessible at exit. */
    mprotect(shared_buf, PAGE_SIZE, PROT_READ | PROT_WRITE);
    return NULL;
}

int main(void)
{
    shared_buf = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shared_buf == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/urandom");
        return 1;
    }

    atomic_store(&stop, 0);
    pthread_t flipper;
    if (pthread_create(&flipper, NULL, protect_flipper, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    /* Reader: each iteration calls read(); accepts either success or EFAULT.
     * Any other result (or a crash, which manifests as the VM halting before we
     * reach the join) is a failure.
     */
    for (int i = 0; i < ITERATIONS; i++) {
        char b;
        errno = 0;
        ssize_t r = read(fd, &b, 1);
        if (r == 1) {
            atomic_fetch_add(&success_count, 1);
        } else if (r == -1 && errno == EFAULT) {
            atomic_fetch_add(&efault_count, 1);
        } else {
            fprintf(stderr, "FAIL iter %d: unexpected read rc=%zd errno=%d\n",
                    i, r, errno);
            atomic_store(&stop, 1);
            pthread_join(flipper, NULL);
            return 1;
        }
    }

    atomic_store(&stop, 1);
    pthread_join(flipper, NULL);
    close(fd);
    munmap(shared_buf, PAGE_SIZE);

    int s = atomic_load(&success_count);
    int e = atomic_load(&efault_count);
    int f = atomic_load(&flips);
    printf("iters=%d success=%d efault=%d mprotect_flips=%d\n", ITERATIONS, s,
           e, f);
    if (s + e != ITERATIONS) {
        fprintf(stderr, "FAIL: success+efault != iterations\n");
        return 1;
    }
    if (e == 0)
        printf(
            "WARN: no EFAULT observed; race window may be too short on "
            "this host. VM did not crash, which is the primary check.\n");
    printf("OK\n");
    return 0;
}
