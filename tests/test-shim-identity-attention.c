/*
 * test-shim-identity-attention.c -- SIGALRM survives fast paths.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Slice A of the identity fast-path optimization routes getpid (and the other
 * five identity syscalls) through the EL1 shim without HVC #5. That skips the
 * post-HVC signal_check_timer epilogue in vcpu_run_loop, which is what normally
 * notices a fired guest ITIMER_REAL and queues SIGALRM. Without Slice B's
 * attention flag, a vCPU stuck in a tight getpid loop would never re-enter EL1
 * and SIGALRM would arrive late (worst case: not until the per-iteration vCPU
 * alarm timeout fires, potentially hundreds of milliseconds).
 *
 * This test arms an ITIMER_REAL for 100 ms, then spins for ~1 second OR until
 * SIGALRM fires. It covers both getpid via the raw SVC and a seeded
 * CLOCK_REALTIME vDSO loop, because both fast paths otherwise bypass the HVC
 * epilogue that runs signal_check_timer().
 */

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "raw-syscall.h"

#ifndef __NR_getpid
#define __NR_getpid 172
#endif

static volatile sig_atomic_t alarm_fired;
static struct timespec alarm_ts;

static void on_sigalrm(int sig)
{
    (void) sig;
    clock_gettime(CLOCK_MONOTONIC, (struct timespec *) &alarm_ts);
    alarm_fired = 1;
}

static long ns_diff(const struct timespec *a, const struct timespec *b)
{
    return (long) ((a->tv_sec - b->tv_sec) * 1000000000LL +
                   (a->tv_nsec - b->tv_nsec));
}

static int run_alarm_spin(const char *name, int use_realtime_vdso)
{
    alarm_fired = 0;
    alarm_ts = (struct timespec) {0};
    struct timespec t_arm;

    if (use_realtime_vdso) {
        struct timespec seed;
        clock_gettime(CLOCK_REALTIME, &seed);
    }

    clock_gettime(CLOCK_MONOTONIC, &t_arm);

    struct itimerval iv = {0};
    iv.it_value.tv_sec = 0;
    iv.it_value.tv_usec = 100 * 1000; /* 100 ms */
    if (setitimer(ITIMER_REAL, &iv, NULL) < 0) {
        fprintf(stderr, "FAIL %s setitimer: %s\n", name, strerror(errno));
        return 1;
    }

    /* With attention raised on setitimer arm, fast paths fall back to HVC and
     * signal_check_timer eventually notices the 100 ms expiry. Bound the spin
     * to 1 s so a broken attention path manifests as test failure rather than a
     * hang.
     */
    long iterations = 0;
    while (!alarm_fired) {
        if (use_realtime_vdso) {
            struct timespec now_rt;
            clock_gettime(CLOCK_REALTIME, &now_rt);
        } else {
            (void) raw_syscall0(__NR_getpid);
        }
        iterations++;
        if ((iterations & 0xFFFF) == 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (ns_diff(&now, &t_arm) > 1000000000L)
                break;
        }
    }

    if (!alarm_fired) {
        fprintf(stderr,
                "FAIL %s: SIGALRM did not fire within 1 s (iterations=%ld)\n",
                name, iterations);
        return 1;
    }

    long delivered_ns = ns_diff((struct timespec *) &alarm_ts, &t_arm);
    /* The 100 ms timer should deliver within ~150 ms in practice; grant 300 ms
     * to absorb host scheduling jitter under load.
     */
    if (delivered_ns > 300 * 1000 * 1000L) {
        fprintf(stderr, "FAIL %s: SIGALRM delivered after %ld ns (>300 ms)\n",
                name, delivered_ns);
        return 1;
    }

    printf("OK %s: SIGALRM after %ld ns (iterations=%ld)\n", name, delivered_ns,
           iterations);
    return 0;
}

int main(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = on_sigalrm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGALRM, &sa, NULL) < 0) {
        fprintf(stderr, "FAIL sigaction: %s\n", strerror(errno));
        return 1;
    }

    if (run_alarm_spin("getpid", 0) != 0)
        return 1;
    if (run_alarm_spin("clock_realtime_vdso", 1) != 0)
        return 1;
    return 0;
}
