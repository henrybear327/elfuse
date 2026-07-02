/*
 * x86_64-rosetta-audit.c - Rosetta thread/signal acceptance smoke
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies that translated x86_64 guests still preserve the thread and signal
 * semantics elfuse expects, while pinning Rosetta's documented SA_RESETHAND
 * limitation as a deliberate XFAIL. The shell harness treats exit 41 as the
 * expected limitation signature.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t sigusr1_seen;
static volatile sig_atomic_t worker_tid_seen;
static volatile int thread_value;

static void sigusr1_handler(int sig)
{
    (void) sig;
    sigusr1_seen = 1;
    worker_tid_seen = (sig_atomic_t) syscall(SYS_gettid);
}

static void *thread_main(void *arg)
{
    int *slot = (int *) arg;
    *slot = 0x1234;
    return NULL;
}

static int test_pthread_basic(void)
{
    pthread_t thr;
    thread_value = 0;
    if (pthread_create(&thr, NULL, thread_main, (void *) &thread_value) != 0) {
        perror("pthread_create");
        return 1;
    }
    if (pthread_join(thr, NULL) != 0) {
        perror("pthread_join");
        return 1;
    }
    if (thread_value != 0x1234) {
        fprintf(stderr, "pthread smoke: unexpected thread_value=%d\n",
                thread_value);
        return 1;
    }
    printf("PASS pthread-create-join\n");
    return 0;
}

static int test_signal_block_unblock(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        perror("sigaction");
        return 1;
    }

    sigset_t block, oldmask;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &block, &oldmask) != 0) {
        perror("sigprocmask block");
        return 1;
    }

    sigusr1_seen = 0;
    worker_tid_seen = 0;
    if (syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1) != 0) {
        perror("tgkill");
        return 1;
    }
    if (sigusr1_seen) {
        fprintf(stderr, "signal smoke: SIGUSR1 delivered while blocked\n");
        return 1;
    }

    if (sigprocmask(SIG_SETMASK, &oldmask, NULL) != 0) {
        perror("sigprocmask unblock");
        return 1;
    }

    for (int i = 0; i < 1000 && !sigusr1_seen; i++)
        usleep(1000);

    if (!sigusr1_seen) {
        fprintf(stderr, "signal smoke: pending SIGUSR1 never delivered\n");
        return 1;
    }
    printf("PASS signal-block-unblock\n");
    return 0;
}

static int test_sa_resethand_expected_xfail(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sa.sa_flags = SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        perror("sigaction SA_RESETHAND");
        return 1;
    }

    sigusr1_seen = 0;
    if (kill(getpid(), SIGUSR1) != 0) {
        perror("kill");
        return 1;
    }
    if (!sigusr1_seen) {
        fprintf(stderr, "signal smoke: SA_RESETHAND handler not called\n");
        return 1;
    }

    struct sigaction cur;
    memset(&cur, 0, sizeof(cur));
    if (sigaction(SIGUSR1, NULL, &cur) != 0) {
        perror("sigaction query");
        return 1;
    }
    if (cur.sa_handler == SIG_DFL) {
        printf("PASS sa-resethand-reset\n");
        return 0;
    }

    printf("XFAIL sa-resethand-shadowed\n");
    return 41;
}

int main(void)
{
    if (test_pthread_basic() != 0)
        return 1;
    if (test_signal_block_unblock() != 0)
        return 1;
    return test_sa_resethand_expected_xfail();
}
