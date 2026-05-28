/* test-shim-cred-race.c -- shim identity cache stays consistent under
 * concurrent setuid traffic.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse's permission model rejects setuid/setresuid to any value not
 * already in {real, effective, saved}, which means a guest binary
 * cannot legally toggle between two distinct uids without privileged
 * setup. This test therefore exercises the no-op-publish path: the
 * mutator calls setresuid(uid, uid, uid) in a tight loop while the
 * reader spins on geteuid via the shim's identity fast path.
 *
 * What it pins:
 *
 *   - cred_publish_after runs without corrupting the cache: every
 *     reader observation must equal the initial euid.
 *   - The publish path is wired into the SC_FORWARD setuid family
 *     (a regression that bypasses publish would still pass because
 *     values don't change, but a regression that crashes during the
 *     atomic store would surface as a SIGSEGV or hang).
 *
 * What it does NOT pin (deferred to Slice B's attention bracket):
 *
 *   - True cred-tearing during a multi-field publish. Demonstrating
 *     that requires a setuid path that mutates {uid, euid, gid,
 *     egid} as a coherent group; elfuse's permission model does not
 *     support such a state transition from the guest side.
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "raw-syscall.h"

#ifndef __NR_geteuid
#define __NR_geteuid 175
#endif
#ifndef __NR_setresuid
#define __NR_setresuid 147
#endif

static atomic_int stop;
static atomic_long observed_other;
static long expected_euid;

static void *reader(void *arg)
{
    (void) arg;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        long v = raw_syscall0(__NR_geteuid);
        if (v != expected_euid)
            atomic_store_explicit(&observed_other, v, memory_order_relaxed);
    }
    return NULL;
}

int main(void)
{
    expected_euid = raw_syscall0(__NR_geteuid);
    if (expected_euid < 0) {
        fprintf(stderr, "FAIL: initial geteuid returned %ld\n", expected_euid);
        return 1;
    }
    atomic_store(&observed_other, -1);
    atomic_store(&stop, 0);

    pthread_t tid;
    if (pthread_create(&tid, NULL, reader, NULL) != 0)
        return 1;

    /* 50_000 no-op setresuid calls. Each triggers cred_publish_after
     * on the elfuse side, racing the reader thread.
     */
    for (int i = 0; i < 50000; i++) {
        long r = raw_syscall3(__NR_setresuid, (long) expected_euid,
                              (long) expected_euid, (long) expected_euid);
        if (r != 0) {
            fprintf(stderr, "FAIL setresuid(%ld,%ld,%ld) iter %d: errno %ld\n",
                    expected_euid, expected_euid, expected_euid, i, -r);
            atomic_store(&stop, 1);
            pthread_join(tid, NULL);
            return 1;
        }
    }
    atomic_store(&stop, 1);
    pthread_join(tid, NULL);

    long bad = atomic_load(&observed_other);
    if (bad != -1) {
        fprintf(stderr, "FAIL: reader observed euid %ld (expected %ld)\n", bad,
                expected_euid);
        return 1;
    }

    printf("OK (50000 no-op publishes, no torn read)\n");
    return 0;
}
