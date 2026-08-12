/* Minimal aarch64-linux guest that sleeps, then exits
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Gives a test a guest that is still running a known time after GDB resumes
 * it. test-hello exits within microseconds of the continue packet, which
 * leaves no window in which to drive the GDB stub while the guest runs; the
 * shutdown-path lanes in tests/test-gdbstub.sh need that window to be wide
 * enough to be certain rather than raced.
 *
 * Assemble and link as a static aarch64-linux ELF:
 *   aarch64-unknown-linux-musl-as -o sleep.o sleep.S
 *   aarch64-unknown-linux-musl-ld -T simple.ld -o sleep sleep.o
 */

.text
.global _start
_start:
    /* nanosleep(&req, NULL) */
    adr x0, req         /* req = &timespec */
    mov x1, #0          /* rem = NULL */
    mov x8, #101        /* __NR_nanosleep = 101 */
    svc #0

    /* exit(0) */
    mov x0, #0          /* exit code = 0 */
    mov x8, #93         /* __NR_exit = 93 */
    svc #0

    /* struct timespec is two 64-bit fields on aarch64: tv_sec, tv_nsec. */
.align 3
req:
    .quad 2             /* tv_sec */
    .quad 0             /* tv_nsec */
