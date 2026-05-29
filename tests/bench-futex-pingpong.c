/* Futex ping-pong microbenchmark
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Two threads handing off via FUTEX_WAIT and FUTEX_WAKE on private futexes.
 * Measures the round-trip cost of the core wait/wake hot path. Reports total
 * elapsed time in milliseconds for the configured handoff count.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

#include "raw-syscall.h"

#define HANDOFFS 20000

static volatile int turn_a;
static volatile int turn_b;
static volatile int b_done;

static int child_stack_storage[16384] __attribute__((aligned(16)));

static int child_fn(void *arg)
{
    (void) arg;
    for (int i = 0; i < HANDOFFS; i++) {
        while (__atomic_load_n(&turn_b, __ATOMIC_ACQUIRE) == 0)
            raw_futex_wait((int *) &turn_b, 0);
        __atomic_store_n(&turn_b, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&turn_a, 1, __ATOMIC_RELEASE);
        raw_futex_wake((int *) &turn_a, 1);
    }
    __atomic_store_n(&b_done, 1, __ATOMIC_RELEASE);
    raw_futex_wake((int *) &b_done, 1);
    raw_exit(0);
    return 0;
}

int main(void)
{
    struct timeval start, end;

    /* Allocate a child stack via the local array (already 16-aligned). */
    void *stack_top =
        (char *) child_stack_storage + sizeof(child_stack_storage);

    int ctid = 0;
    long flags = 0x00010f00 | 0x00200000; /* CLONE_VM|FS|FILES|SIGHAND|THREAD|
                                           * SYSVSEM|CHILD_CLEARTID
                                           * matched at raw level.
                                           */
    /* Use the conventional pthread-like flag mask. */
    flags = 0x3D0F00; /* CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS off |
                       * PARENT_SETTID off | CHILD_CLEARTID|CHILD_SETTID.
                       */
    /* Simpler: just CLONE_VM|CLONE_THREAD|CLONE_SIGHAND|CLONE_FS|CLONE_FILES.
     */
    flags = 0x00000100 | 0x00010000 | 0x00000800 | 0x00000200 |
            0x00000400; /* VM|THREAD|SIGHAND|FS|FILES */

    /* aarch64 clone ABI: x0=flags, x1=child_stack, x2=parent_tid,
     * x3=tls, x4=child_tid. The child returns at the same site.
     */
    long rc = raw_clone((unsigned long) flags, stack_top, NULL, 0, &ctid);
    if (rc == 0) {
        child_fn(NULL);
        /* unreachable */
        return 0;
    }
    if (rc < 0) {
        fprintf(stderr, "clone failed: %ld\n", rc);
        return 1;
    }

    gettimeofday(&start, NULL);

    /* Kick off the round-trip. */
    __atomic_store_n(&turn_b, 1, __ATOMIC_RELEASE);
    raw_futex_wake((int *) &turn_b, 1);

    for (int i = 0; i < HANDOFFS; i++) {
        while (__atomic_load_n(&turn_a, __ATOMIC_ACQUIRE) == 0)
            raw_futex_wait((int *) &turn_a, 0);
        __atomic_store_n(&turn_a, 0, __ATOMIC_RELEASE);
        if (i + 1 < HANDOFFS) {
            __atomic_store_n(&turn_b, 1, __ATOMIC_RELEASE);
            raw_futex_wake((int *) &turn_b, 1);
        }
    }

    /* Wait for child to finish so timing covers full handoff count. */
    while (__atomic_load_n(&b_done, __ATOMIC_ACQUIRE) == 0)
        raw_futex_wait((int *) &b_done, 0);

    gettimeofday(&end, NULL);

    long elapsed_us =
        (end.tv_sec - start.tv_sec) * 1000000L + (end.tv_usec - start.tv_usec);
    /* Print elapsed time in milliseconds (3 decimal places). */
    long ms_int = elapsed_us / 1000;
    long ms_frac = elapsed_us % 1000;
    printf("elapsed_ms %ld.%03ld\n", ms_int, ms_frac);
    return 0;
}
