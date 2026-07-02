/*
 * test-mremap-infra.c -- mremap/madvise must reject ranges hitting infra
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The infrastructure reserve at the top of guest IPA holds page tables, the EL1
 * shim's code, and the shim's data block. None of these are legal targets for
 * guest memory management. sys_mmap MAP_FIXED, sys_munmap and sys_mprotect
 * already enforce this via guest_range_hits_infra; sys_mremap and sys_madvise
 * did not, leaving a spoofing/corruption vector for code that knows the infra
 * GVA.
 *
 * This test exercises the four guarded variants:
 *   1. mremap source range hits infra
 *   2. mremap MREMAP_FIXED destination hits infra
 *   3. mremap grow-in-place tail spills into infra
 *   4. madvise(MADV_DONTNEED) on an infra range
 *
 * All four must fail with EINVAL. The infra base is read at runtime from
 * /proc/self/maps so the test stays portable across the 36-bit and 40-bit IPA
 * configurations.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif

#define PAGE_SIZE 4096

static int failures = 0;

#define EXPECT(cond, msg)                       \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, "FAIL: %s\n", msg); \
            failures++;                         \
        }                                       \
    } while (0)

/* Parse the lower bound of the named region from /proc/self/maps.
 * /proc/self/maps lines look like:
 *   ffffffc00000-ffffffc00400 r-xp 00000000 00:00 0          [shim]
 * Returns 0 if not found.
 */
static uint64_t find_region_base(const char *name)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return 0;
    char line[512];
    uint64_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, name)) {
            unsigned long long lo = 0;
            if (sscanf(line, "%llx-", &lo) == 1) {
                base = lo;
                break;
            }
        }
    }
    fclose(fp);
    return base;
}

int main(void)
{
    printf("test-mremap-infra: mremap/madvise reject infra-range targets\n");

    /* Locate [shim-data]; if absent, [shim] is also acceptable as the infra
     * reserve covers both. The test only needs ANY infra GVA.
     */
    uint64_t infra = find_region_base("[shim-data]");
    if (!infra)
        infra = find_region_base("[shim]");
    if (!infra) {
        fprintf(stderr,
                "FAIL: could not locate infra region in /proc/self/maps\n");
        return 1;
    }
    printf("infra base = 0x%llx\n", (unsigned long long) infra);

    /* Allocate a scratch mapping to use as the source for mremap variants. */
    void *src = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (src == MAP_FAILED) {
        fprintf(stderr, "FAIL: scratch mmap: %s\n", strerror(errno));
        return 1;
    }

    /* Case 1: mremap source range hits infra. The source must be a legal VMA
     * for mremap to consider it, but pointing the call directly at the infra
     * base is enough to make the kernel try.
     */
    errno = 0;
    void *r = mremap((void *) (uintptr_t) infra, PAGE_SIZE, PAGE_SIZE,
                     MREMAP_MAYMOVE);
    EXPECT(r == MAP_FAILED && errno == EINVAL,
           "mremap source==infra rejected with EINVAL");

    /* Case 2: MREMAP_FIXED destination hits infra. */
    errno = 0;
    r = mremap(src, PAGE_SIZE, PAGE_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED,
               (void *) (uintptr_t) infra);
    EXPECT(r == MAP_FAILED && errno == EINVAL,
           "mremap MREMAP_FIXED dest==infra rejected with EINVAL");

    /* Case 3: grow-in-place tail spills into infra. Map a one-page region
     * immediately below the infra base (assumes nothing else sits in that hole;
     * if it does, the test is inconclusive but still safe).
     */
    void *base = (void *) (uintptr_t) (infra - PAGE_SIZE);
    void *p = mmap(base, PAGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p != MAP_FAILED) {
        errno = 0;
        r = mremap(p, PAGE_SIZE, 2 * PAGE_SIZE, 0);
        EXPECT(r == MAP_FAILED && errno == EINVAL,
               "mremap grow-in-place into infra rejected with EINVAL");
        munmap(p, PAGE_SIZE);
    } else {
        printf(
            "SKIP grow-in-place: cannot place sentinel mapping (already "
            "taken)\n");
    }

    /* Case 4: madvise(MADV_DONTNEED) on an infra range. */
    errno = 0;
    int rc = madvise((void *) (uintptr_t) infra, PAGE_SIZE, MADV_DONTNEED);
    EXPECT(rc == -1 && errno == EINVAL,
           "madvise(MADV_DONTNEED) on infra rejected with EINVAL");

    munmap(src, PAGE_SIZE);

    if (failures) {
        fprintf(stderr, "FAIL: %d check(s) failed\n", failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
