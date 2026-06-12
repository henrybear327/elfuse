/* x86_64-glibc-gdtls.c - General-dynamic TLS probe for the Rosetta gate
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * dlopen() the companion shared library (libgdtls.so), pull its gdtls_get /
 * gdtls_set accessors via dlsym, exercise the __thread variable across
 * set/read/re-set/read. Because the library is loaded after main() starts, its
 * __thread storage uses the general-dynamic model (calls into __tls_get_addr)
 * rather than initial-exec; a broken Rosetta lowering of that path surfaces as
 * a value mismatch.
 *
 * Build (on an x86_64 Linux host):
 *   gcc -O2 -ldl -o gdtls-probe x86_64-glibc-gdtls.c
 *
 * libgdtls.so must sit on the dynamic loader search path at runtime; the test
 * rootfs stages it under /lib/x86_64-linux-gnu/.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static void emit(int fd, const char *s)
{
    ssize_t n = write(fd, s, strlen(s));
    if (n > 0)
        n = write(fd, "\n", 1);
    (void) n;
}

int main(void)
{
    void *h = dlopen("libgdtls.so", RTLD_NOW);
    if (!h) {
        const char *err = dlerror();
        emit(STDERR_FILENO, err ? err : "dlopen-failed");
        return 1;
    }

    uint64_t (*get_fn)(void);
    void (*set_fn)(uint64_t);
    void *raw_get = dlsym(h, "gdtls_get");
    void *raw_set = dlsym(h, "gdtls_set");
    if (!raw_get || !raw_set) {
        const char *err = dlerror();
        emit(STDERR_FILENO, err ? err : "dlsym-failed");
        (void) dlclose(h);
        return 2;
    }
    memcpy((void *) &get_fn, (const void *) &raw_get, sizeof(get_fn));
    memcpy((void *) &set_fn, (const void *) &raw_set, sizeof(set_fn));

    /* Initial-state read goes through __tls_get_addr on the dlopened image's
     * PT_TLS template.
     */
    if (get_fn() != 0x0123456789abcdefULL) {
        emit(STDERR_FILENO, "gdtls-initial-read-wrong");
        (void) dlclose(h);
        return 3;
    }

    set_fn(0xdeadbeefcafef00dULL);
    if (get_fn() != 0xdeadbeefcafef00dULL) {
        emit(STDERR_FILENO, "gdtls-write-readback-wrong");
        (void) dlclose(h);
        return 4;
    }

    if (dlclose(h) != 0) {
        emit(STDERR_FILENO, "dlclose-failed");
        return 5;
    }

    static const char ok[] = "glibc-gdtls-ok\n";
    if (write(STDOUT_FILENO, ok, sizeof(ok) - 1) != (ssize_t) sizeof(ok) - 1)
        return 6;
    return 0;
}
