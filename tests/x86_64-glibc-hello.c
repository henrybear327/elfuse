/* x86_64-glibc-hello.c - Minimal glibc dynamic hello for Rosetta smoke
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>

int main(void)
{
    static const char msg[] = "glibc-hello-ok\n";
    if (write(STDOUT_FILENO, msg, sizeof(msg) - 1) != (ssize_t) sizeof(msg) - 1)
        return 1;
    return 0;
}
