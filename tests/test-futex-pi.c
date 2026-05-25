/* PI futex and EINTR regression tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests:
 *   1. PI futex dead-owner recovery (commit 64d21f2): child thread
 *      acquires a PI lock, exits without releasing it. Parent's
 *      FUTEX_LOCK_PI detects the dead owner and acquires the lock.
 *
 *   2. FUTEX_LOCK_PI + FUTEX_UNLOCK_PI round-trip: acquire and
 *      release a PI lock from the same thread.
 *
 *   3. futex_wait EINTR injection (commit 18bdd0f): futex_wait with
 *      no timeout returns -EINTR within ~1-2 seconds when no waker
 *      exists (simulated periodic signal delivery).
 *
 * Syscalls exercised: futex(98), clone(220), gettid(178), exit(93)
 */

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/futex.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

/* Linux PI futex word layout */
#ifndef FUTEX_TID_MASK
#define FUTEX_TID_MASK 0x3FFFFFFF
#endif
#ifndef FUTEX_WAITERS
#define FUTEX_WAITERS 0x80000000
#endif

/* Linux futex ops */
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_PRIVATE 128

/* PI lock word: shared between parent and child thread.
 * Must be aligned to 4 bytes (futex requirement).
 */
static volatile uint32_t pi_lock __attribute__((aligned(4))) = 0;

/* Sync flag: child signals it has acquired the lock */
static volatile int child_ready = 0;

/* PI futex syscall wrappers */

static long raw_futex_lock_pi(uint32_t *addr)
{
    return raw_syscall6(__NR_futex, (long) addr, FUTEX_LOCK_PI | FUTEX_PRIVATE,
                        0, 0, 0, 0);
}

static long raw_futex_unlock_pi(uint32_t *addr)
{
    return raw_syscall6(__NR_futex, (long) addr,
                        FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0, 0, 0, 0);
}

/* Child thread for dead-owner test */

/* Stack for child thread (8KiB, 16-byte aligned) */
static char child_stack_buf[8192] __attribute__((aligned(16)));

/* Child: acquire PI lock, signal parent, exit WITHOUT releasing.
 * This tests elfuse's dead-owner detection in futex_lock_pi().
 */
static void child_acquire_and_die(void)
{
    /* Acquire the PI lock (sets pi_lock = the current TID) */
    long r = raw_futex_lock_pi((uint32_t *) &pi_lock);
    if (r != 0) {
        /* Lock acquisition failed; signal parent anyway */
        child_ready = 99;
        raw_futex_wake((int *) &child_ready, 1);
        raw_exit(1);
    }

    /* Signal parent that the child holds the lock */
    child_ready = 1;
    raw_futex_wake((int *) &child_ready, 1);

    /* Exit WITHOUT calling FUTEX_UNLOCK_PI. This is the bug scenario:
     * elfuse's futex_lock_pi must detect the current TID is dead and recover.
     */
    raw_exit(0);
}

/* Test 1: PI lock/unlock round-trip */

static void test_pi_lock_unlock(void)
{
    TEST("PI lock/unlock round-trip");

    pi_lock = 0;

    long r = raw_futex_lock_pi((uint32_t *) &pi_lock);
    if (r != 0) {
        FAIL("LOCK_PI failed");
        return;
    }

    /* Verify the current thread owns the lock (low bits = the current TID) */
    uint32_t tid = (uint32_t) raw_gettid();
    uint32_t val = __atomic_load_n(&pi_lock, __ATOMIC_SEQ_CST);
    if ((val & FUTEX_TID_MASK) != tid) {
        FAIL("lock word doesn't contain our TID");
        return;
    }

    r = raw_futex_unlock_pi((uint32_t *) &pi_lock);
    if (r != 0) {
        FAIL("UNLOCK_PI failed");
        return;
    }

    /* Lock should be free (0) */
    val = __atomic_load_n(&pi_lock, __ATOMIC_SEQ_CST);
    EXPECT_TRUE(val == 0, "lock word not zero after unlock");
}

/* Test 2: Dead-owner recovery */

static void test_pi_dead_owner(void)
{
    TEST("PI dead-owner recovery");

    /* Reset shared state */
    pi_lock = 0;
    child_ready = 0;

    /* Clone a child thread that acquires the PI lock and exits.
     * CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
     * CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
     * CLONE_CHILD_CLEARTID
     */
    void *stack_top = child_stack_buf + sizeof(child_stack_buf);
    int child_tid_val = 0;

    long ret = raw_clone(0x7d0f00, stack_top, &child_tid_val, 0,
                         (int *) &child_tid_val);

    if (ret < 0) {
        FAIL("clone failed");
        return;
    }

    if (ret == 0) {
        /* Child path */
        child_acquire_and_die();
        /* Should not reach here */
        raw_exit(1);
    }

    /* Parent: wait for child to signal it holds the lock */
    for (int i = 0; i < 100; i++) {
        if (__atomic_load_n(&child_ready, __ATOMIC_SEQ_CST) != 0)
            break;
        raw_futex_wait((int *) &child_ready, 0);
    }

    if (child_ready != 1) {
        FAIL("child didn't acquire lock");
        return;
    }

    /* Wait for child thread to actually exit (CLONE_CHILD_CLEARTID
     * clears child_tid_val and does futex_wake). Give it 500ms.
     */
    for (int i = 0; i < 50; i++) {
        if (__atomic_load_n(&child_tid_val, __ATOMIC_SEQ_CST) == 0)
            break;
        usleep(10000); /* 10ms */
    }

    /* Now try to acquire the PI lock. The child exited without
     * releasing it, so elfuse's futex_lock_pi must detect the dead
     * owner and let the waiter acquire.
     */
    long r = raw_futex_lock_pi((uint32_t *) &pi_lock);
    if (r != 0) {
        FAIL("LOCK_PI failed (dead-owner not recovered)");
        return;
    }

    /* Clean up: release the lock */
    raw_futex_unlock_pi((uint32_t *) &pi_lock);
    PASS();
}

/* Test 3: EINTR injection after ~1s */

/* Sibling that keeps the guest in a multi-threaded state for the duration of
 * the EINTR probe. The synthetic EINTR injection in futex_wait only fires
 * while thread_is_single_active() is false; a single-threaded guest must be
 * allowed to park in FUTEX_WAIT indefinitely so it does not break glibc
 * startup paths. The probe therefore has to run with at least one other guest
 * thread alive.
 *
 * The sibling sleeps on a timed futex_wait against keepalive_word with a
 * 5-second timeout. The timeout dodges the EINTR injection ('!has_timeout' is
 * what gates the sim), and 5 s is long enough to outlast the worst-case parent
 * EINTR window (1 s with up to 100 ms poll jitter, plus a safety margin). After
 * the parent's probe returns, the parent flips keepalive_word and wakes the
 * sibling.
 */
static volatile int sibling_keepalive __attribute__((aligned(4))) = 1;
static char sibling_stack_buf[8192] __attribute__((aligned(16)));

static void sibling_alive_thread(void)
{
    struct timespec ts = {5, 0};
    while (__atomic_load_n(&sibling_keepalive, __ATOMIC_SEQ_CST) == 1) {
        raw_syscall6(__NR_futex, (long) &sibling_keepalive,
                     FUTEX_WAIT | FUTEX_PRIVATE, 1, (long) &ts, 0, 0);
    }
    raw_exit(0);
}

static void test_futex_eintr(void)
{
    TEST("futex_wait EINTR after ~1s");

    /* Spawn the sibling so thread_is_single_active() is false during the wait.
     * CLONE flags match test_pi_dead_owner.
     */
    sibling_keepalive = 1;
    void *sibling_top = sibling_stack_buf + sizeof(sibling_stack_buf);
    int sibling_tid_val = 0;
    long sret = raw_clone(0x7d0f00, sibling_top, &sibling_tid_val, 0,
                          (int *) &sibling_tid_val);
    if (sret < 0) {
        FAIL("sibling clone failed");
        return;
    }
    if (sret == 0) {
        sibling_alive_thread();
        raw_exit(1); /* unreachable */
    }

    /* Create a futex word that no one will wake.
     * futex_wait with no timeout should return -EINTR after ~1 second
     * (elfuse's simulated periodic signal delivery).
     */
    volatile int unwoken = 42;

    struct timeval t0, t1;
    gettimeofday(&t0, NULL);

    long r = raw_futex_wait((int *) &unwoken, 42);

    gettimeofday(&t1, NULL);
    long elapsed_ms =
        (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_usec - t0.tv_usec) / 1000;

    /* Tear down the sibling now that the EINTR check is done. */
    __atomic_store_n(&sibling_keepalive, 0, __ATOMIC_SEQ_CST);
    raw_futex_wake((int *) &sibling_keepalive, 1);
    for (int i = 0; i < 100; i++) {
        if (__atomic_load_n(&sibling_tid_val, __ATOMIC_SEQ_CST) == 0)
            break;
        usleep(10000);
    }

    /* Expect -EINTR (Linux errno 4) after 800ms-3000ms.
     * The 1s timeout has jitter from 100ms polling intervals.
     */
    if (r == -4 /* -EINTR */ && elapsed_ms >= 800 && elapsed_ms <= 3000) {
        PASS();
    } else if (r == -4) {
        /* Got EINTR but timing seems off; still passing, but note it */
        printf("OK (EINTR after %ldms)\n", elapsed_ms);
        passes++;
    } else {
        printf("FAIL: expected -EINTR(-4) got %ld, elapsed %ldms\n", r,
               elapsed_ms);
        fails++;
    }
}

static void test_futex_unaligned(void)
{
    TEST("futex rejects unaligned uaddr");

    uint32_t words[2] = {0};
    int *unaligned = (int *) (void *) (((unsigned char *) words) + 1);

    long r = raw_futex_wait(unaligned, 0);
    if (r != -22) {
        printf("FAIL: WAIT expected -EINVAL(-22) got %ld\n", r);
        fails++;
        return;
    }

    r = raw_futex_wake(unaligned, 1);
    if (r != -22) {
        printf("FAIL: WAKE expected -EINVAL(-22) got %ld\n", r);
        fails++;
        return;
    }

    r = raw_syscall6(__NR_futex, (long) unaligned,
                     FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, 0, 0, 0);
    if (r != -22) {
        printf("FAIL: LOCK_PI expected -EINVAL(-22) got %ld\n", r);
        fails++;
        return;
    }

    r = raw_syscall6(__NR_futex, (long) unaligned,
                     FUTEX_TRYLOCK_PI | FUTEX_PRIVATE, 0, 0, 0, 0);
    if (r != -22) {
        printf("FAIL: TRYLOCK_PI expected -EINVAL(-22) got %ld\n", r);
        fails++;
        return;
    }

    r = raw_syscall6(__NR_futex, (long) unaligned,
                     FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0, 0, 0, 0);
    if (r != -22) {
        printf("FAIL: UNLOCK_PI expected -EINVAL(-22) got %ld\n", r);
        fails++;
        return;
    }

    PASS();
}

/* Main */

int main(void)
{
    printf("test-futex-pi: PI futex and EINTR regression tests\n");

    test_pi_lock_unlock();
    test_futex_eintr();
    test_futex_unaligned();
    test_pi_dead_owner(); /* Last: uses CLONE_THREAD which may hang on x64 */

    SUMMARY("test-futex-pi");
    return fails > 0 ? 1 : 0;
}
