/*
 * x86_64-glibc-dlopen.c - Runtime dlopen probe for the Rosetta gate
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The hello/--list probes only exercise load-time PT_INTERP and ld.so
 * introspection. Runtime dlopen takes a different elfuse codepath: a fresh
 * anonymous-then-file mmap into the gap-finding allocator, not the high-VA
 * fixed-mmap replacement path the static probe touches. The success line is the
 * only signal; everything else is stderr-only so the consumer regex stays
 * trivial.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static void emit(int fd, const char *s)
{
    /* warn_unused_result on glibc's write() prototype is not suppressed by
     * (void) cast, so route the return through a sink variable that gets read
     * once at function exit.
     */
    ssize_t n = write(fd, s, strlen(s));
    if (n > 0)
        n = write(fd, "\n", 1);
    (void) n;
}

int main(void)
{
    void *h = dlopen("libm.so.6", RTLD_NOW);
    if (!h) {
        const char *err = dlerror();
        emit(STDERR_FILENO, err ? err : "dlopen-failed");
        return 1;
    }

    /* dlsym -> function pointer cannot be expressed as a single ISO C
     * conversion; the POSIX-2013 idiom is to copy the bits across a void* slot.
     * The static_assert keeps the cast honest if a future platform ever changes
     * pointer sizes.
     */
    _Static_assert(sizeof(void *) == sizeof(double (*)(double)),
                   "void* and function pointer width mismatch");
    double (*sqrt_fn)(double);
    void *raw = dlsym(h, "sqrt");
    if (!raw) {
        const char *err = dlerror();
        emit(STDERR_FILENO, err ? err : "dlsym-failed");
        (void) dlclose(h);
        return 2;
    }
    memcpy((void *) &sqrt_fn, (const void *) &raw, sizeof(sqrt_fn));

    if (sqrt_fn(16.0) != 4.0) {
        emit(STDERR_FILENO, "sqrt-mismatch");
        (void) dlclose(h);
        return 3;
    }

    if (dlclose(h) != 0) {
        emit(STDERR_FILENO, "dlclose-failed");
        return 4;
    }

    static const char ok[] = "glibc-dlopen-ok\n";
    if (write(STDOUT_FILENO, ok, sizeof(ok) - 1) != (ssize_t) sizeof(ok) - 1)
        return 5;
    return 0;
}
