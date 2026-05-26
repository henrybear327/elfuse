/* x86_64-glibc-tls.c - Initial-exec TLS probe for the Rosetta gate
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * x86-64 reads thread-local storage through the FS segment register;
 * Rosetta has to translate those accesses into TPIDR_EL0-relative
 * loads when it lowers x86 to aarch64. The hello/dlopen probes never
 * touch FS-relative addressing, so this is the first elfuse probe
 * that actually exercises that translation. Two __thread variables
 * cover both the integer and pointer access shapes the compiler
 * emits; a value-mismatch failure here typically points at a broken
 * FS-to-TPIDR_EL0 plumbing inside the translator path, not at glibc
 * or elfuse mmap.
 */

#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* Initial-exec model: the variables live in the main executable, so
 * the compiler emits direct fs:offset loads. No libpthread needed.
 */
static __thread uint32_t tls_int = 0xdeadbeef;
static __thread const char *tls_ptr = "tls-pointer-ok";

static void emit(int fd, const char *s)
{
    /* warn_unused_result on glibc's write() prototype is not suppressed
     * by (void) cast, so route the return through a sink variable that
     * gets read once at function exit.
     */
    ssize_t n = write(fd, s, strlen(s));
    if (n > 0)
        n = write(fd, "\n", 1);
    (void) n;
}

int main(void)
{
    if (tls_int != 0xdeadbeef) {
        emit(STDERR_FILENO, "tls-int-init-wrong");
        return 1;
    }
    tls_int = 0xfeedface;
    if (tls_int != 0xfeedface) {
        emit(STDERR_FILENO, "tls-int-write-readback-wrong");
        return 2;
    }

    if (!tls_ptr || strcmp(tls_ptr, "tls-pointer-ok") != 0) {
        emit(STDERR_FILENO, "tls-ptr-init-wrong");
        return 3;
    }
    tls_ptr = "tls-pointer-updated";
    if (strcmp(tls_ptr, "tls-pointer-updated") != 0) {
        emit(STDERR_FILENO, "tls-ptr-write-readback-wrong");
        return 4;
    }

    static const char ok[] = "glibc-tls-ok\n";
    if (write(STDOUT_FILENO, ok, sizeof(ok) - 1) != (ssize_t) sizeof(ok) - 1)
        return 5;
    return 0;
}
