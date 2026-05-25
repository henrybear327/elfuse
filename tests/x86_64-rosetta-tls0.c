/* x86_64-rosetta-tls0.c - CLONE_SETTLS tls=0 reproducer for Rosetta
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The shell harness expects this program to hang under Rosetta and kills it
 * with timeout(1). If Rosetta ever stops hanging here, the harness should be
 * updated together with the documented limitation table.
 */

#include <stdint.h>

#include "raw-syscall.h"

static volatile int child_done;
static volatile int child_tid;
static unsigned char child_stack[8192] __attribute__((aligned(16)));

int main(void)
{
    void *stack_top = child_stack + sizeof(child_stack);
    long ret = raw_clone(0x7d0f00UL, stack_top, (int *) &child_tid, 0,
                         (int *) &child_tid);
    if (ret == 0) {
        child_done = 1;
        raw_exit(0);
        __builtin_unreachable();
    }
    if (ret < 0)
        return 2;

    for (;;)
        raw_futex_wait((int *) &child_done, 0);
}
