/* test-shim-urandom-smp.c -- multi-thread urandom-read stress.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The shim's urandom-read fast path advances a shared ring head via
 * LDXR/STXR. Concurrent vCPUs reading /dev/urandom must:
 *   1. Never see a torn or zero-filled byte (host always refills
 *      with arc4random_buf output).
 *   2. Never observe the same byte sequence as a sibling thread
 *      (each thread's atomic head-advance reserves its own slice
 *      of the ring).
 *   3. Keep the head from overflowing or underflowing the ring.
 *
 * Each thread reads N 1-byte samples and records them in a private
 * histogram. After the run we check:
 *   - Total bytes consumed across all threads equals N * threads.
 *   - No thread's per-byte distribution is degenerate (all-zero or
 *     all-one buckets indicate the fast path served stale memory).
 *   - The sums across threads differ from each other (a hard test
 *     that the threads are actually getting independent bytes).
 *
 * The test runs only under elfuse, where the urandom fast path is
 * live; on native Linux the read() goes straight to the kernel and
 * the same invariants hold trivially.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NTHREADS 4
#define NSAMPLES 16384

typedef struct {
    int fd;
    int tid_index;
    int histogram[256];
    uint64_t sum;
} worker_arg_t;

static void *worker(void *arg)
{
    worker_arg_t *w = arg;
    char b;
    for (int i = 0; i < NSAMPLES; i++) {
        ssize_t r = read(w->fd, &b, 1);
        if (r != 1) {
            fprintf(stderr,
                    "FAIL thread %d iter %d: read returned %zd "
                    "(errno=%d)\n",
                    w->tid_index, i, r, errno);
            return (void *) (uintptr_t) 1;
        }
        unsigned char ub = (unsigned char) b;
        w->histogram[ub]++;
        w->sum += ub;
    }
    return NULL;
}

int main(void)
{
    /* One shared fd: every thread shares the same FD_URANDOM slot,
     * so the shim's fast path is exercised on the same bitmap bit
     * by all threads simultaneously.
     */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/urandom");
        return 1;
    }

    worker_arg_t workers[NTHREADS];
    pthread_t threads[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
        memset(&workers[i], 0, sizeof(workers[i]));
        workers[i].fd = fd;
        workers[i].tid_index = i;
        if (pthread_create(&threads[i], NULL, worker, &workers[i]) != 0) {
            fprintf(stderr, "FAIL pthread_create %d: %s\n", i, strerror(errno));
            return 1;
        }
    }

    int failures = 0;
    for (int i = 0; i < NTHREADS; i++) {
        void *rc = NULL;
        pthread_join(threads[i], &rc);
        if (rc != NULL) {
            failures++;
            continue;
        }
        /* Per-thread distribution sanity: each bucket should be
         * roughly NSAMPLES / 256 = 64 with stddev about 8. Flag any
         * thread whose distribution is wildly off.
         */
        int min = NSAMPLES, max = 0, zeros = 0;
        for (int b = 0; b < 256; b++) {
            int c = workers[i].histogram[b];
            if (c < min)
                min = c;
            if (c > max)
                max = c;
            if (c == 0)
                zeros++;
        }
        printf("thread %d: sum=%llu min=%d max=%d zero-buckets=%d\n", i,
               (unsigned long long) workers[i].sum, min, max, zeros);
        if (max == NSAMPLES) {
            fprintf(stderr, "FAIL thread %d: all bytes identical\n", i);
            failures++;
        }
        if (zeros > 32) {
            fprintf(stderr, "FAIL thread %d: %d unused buckets (degenerate)\n",
                    i, zeros);
            failures++;
        }
    }
    close(fd);

    /* Threads must have seen different total sums. Equal sums imply
     * they consumed identical byte sequences, which means the shim's
     * head-advance lost the race or served stale ring data.
     */
    for (int i = 0; i < NTHREADS; i++) {
        for (int j = i + 1; j < NTHREADS; j++) {
            if (workers[i].sum == workers[j].sum) {
                fprintf(stderr,
                        "FAIL threads %d and %d have identical sum=%llu\n", i,
                        j, (unsigned long long) workers[i].sum);
                failures++;
            }
        }
    }

    if (failures) {
        fprintf(stderr, "FAIL: %d issue(s)\n", failures);
        return 1;
    }
    printf("OK: %d threads x %d 1B reads each, ring stayed consistent\n",
           NTHREADS, NSAMPLES);
    return 0;
}
