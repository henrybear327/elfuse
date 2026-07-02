/*
 * x86_64-glibc-pthread-tls.c - pthread per-thread TLS probe
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Each thread under pthread gets its own TLS block; on x86_64 the FS-register
 * points at a different address per thread. Rosetta has to wire that per-thread
 * FS to a per-thread TPIDR_EL0 when it lowers the guest. The single-thread
 * initial-exec probe (glibc-tls) only exercises the main thread's setup; this
 * probe asserts that a worker thread sees its own isolated TLS slot and that
 * the main thread's slot is not clobbered by the worker.
 *
 * Build (on an x86_64 Linux host):
 *   gcc -O2 -pthread -o pthread-tls-probe x86_64-glibc-pthread-tls.c
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static __thread uint64_t per_thread_value = 0xa5a5a5a5a5a5a5a5ULL;

static void emit(int fd, const char *s)
{
    ssize_t n = write(fd, s, strlen(s));
    if (n > 0)
        n = write(fd, "\n", 1);
    (void) n;
}

struct worker_result {
    uint64_t initial;     /* per_thread_value as the worker first sees it */
    uint64_t after_write; /* per_thread_value after the worker writes its
                           * own marker */
};

static void *worker(void *arg)
{
    struct worker_result *r = (struct worker_result *) arg;
    r->initial = per_thread_value;
    per_thread_value = 0xbeefcafe12345678ULL;
    r->after_write = per_thread_value;
    return NULL;
}

int main(void)
{
    /* Main thread's TLS slot starts at the default value. Write a different
     * marker so we can prove the worker's write does not bleed across.
     */
    if (per_thread_value != 0xa5a5a5a5a5a5a5a5ULL) {
        emit(STDERR_FILENO, "main-initial-wrong");
        return 1;
    }
    per_thread_value = 0xdeadbeefdeadbeefULL;

    struct worker_result wr = {0, 0};
    pthread_t th;
    if (pthread_create(&th, NULL, worker, &wr) != 0) {
        emit(STDERR_FILENO, "pthread-create-failed");
        return 2;
    }
    if (pthread_join(th, NULL) != 0) {
        emit(STDERR_FILENO, "pthread-join-failed");
        return 3;
    }

    /* Worker must have seen its own default (not main's overwritten marker),
     * and its own write must have stayed in its slot.
     */
    if (wr.initial != 0xa5a5a5a5a5a5a5a5ULL) {
        emit(STDERR_FILENO, "worker-initial-not-isolated");
        return 4;
    }
    if (wr.after_write != 0xbeefcafe12345678ULL) {
        emit(STDERR_FILENO, "worker-write-readback-wrong");
        return 5;
    }
    /* Main's slot must still hold the value we wrote before pthread _create,
     * untouched by the worker's write.
     */
    if (per_thread_value != 0xdeadbeefdeadbeefULL) {
        emit(STDERR_FILENO, "main-slot-clobbered");
        return 6;
    }

    static const char ok[] = "glibc-pthread-tls-ok\n";
    if (write(STDOUT_FILENO, ok, sizeof(ok) - 1) != (ssize_t) sizeof(ok) - 1)
        return 7;
    return 0;
}
