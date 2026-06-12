/* x86_64-glibc-gdtls-lib.c - Shared object with a general-dynamic thread-local
 * variable, paired with x86_64-glibc-gdtls.c.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The probe binary dlopens this .so at runtime. A dlopen-loaded .so cannot use
 * the initial-exec TLS model that the main executable's __thread variables use;
 * the compiler emits a general-dynamic access sequence that calls
 * __tls_get_addr() at runtime. This .so therefore exercises a TLS lowering path
 * the existing initial-exec probe in glibc-tls cannot reach.
 *
 * Build (on an x86_64 Linux host):
 *   gcc -O2 -fPIC -shared -o libgdtls.so x86_64-glibc-gdtls-lib.c
 */

#include <stdint.h>

/* The general-dynamic TLS model is explicitly forced here. With just 'static
 * __thread' the compiler is free to pick local-dynamic for a file-scope symbol
 * inside a shared object, which would still call __tls_get_addr but through a
 * different relocation sequence. Dropping 'static' makes the symbol externally
 * visible (which prevents LD relaxation) and the tls_model attribute pins the
 * codegen so the vendored .so cannot silently regress to LD when rebuilt with a
 * different compiler.
 */
__attribute__((tls_model("global-dynamic"))) __thread uint64_t gdtls_value =
    0x0123456789abcdefULL;

uint64_t gdtls_get(void)
{
    return gdtls_value;
}

void gdtls_set(uint64_t v)
{
    gdtls_value = v;
}
