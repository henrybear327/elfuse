/*
 * mkdir helper
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Create each argv path (mode 0755), tolerating EEXIST. Sysroot recipes run
 * this as a guest so a directory is created through the guest, which on a
 * case-insensitive volume mints its sidecar token; a later run then resolves
 * that name through the tokenized on-disk index.
 */

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        if (mkdir(argv[i], 0755) != 0 && errno != EEXIST) {
            perror(argv[i]);
            return 1;
        }
    return 0;
}
