/*
 * Unmapped sidecar token visibility
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A `.ef_<16 hex>` file with no row in its directory's index is an ordinary
 * file to the guest, not hidden state. Lookup falls back to the literal on-disk
 * spelling whenever the index has no row, which is what lets host-staged names
 * work at all, so that same fallback reaches a token-shaped name. It must
 * therefore appear in a listing under that spelling: hiding it would make a
 * file the guest can stat and open impossible to enumerate.
 *
 * This is the rule both dirent consumers follow. getdents64 passes an unmapped
 * name through, and the inotify snapshot does the same, so a listing and an
 * event name agree with each other and with lookup.
 *
 * The orphan is staged by the recipe because the guest cannot create one: every
 * guest-created name is registered in the index as it is written.
 *
 * Run under --sysroot on a case-insensitive volume, so the sidecar is active.
 */

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define STAGE_DIR "/data"
#define ORPHAN_TOKEN ".ef_0123456789abcdef"
#define PLAIN_NAME "Plain.Host"

int main(void)
{
    DIR *d = opendir(STAGE_DIR);
    if (!d) {
        printf("test-sidecar-orphan: cannot open %s (errno=%d)\n", STAGE_DIR,
               errno);
        return 1;
    }

    bool saw_orphan = false, saw_plain = false, saw_index = false;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strncmp(de->d_name, ".ef_", 4))
            saw_orphan = true;
        if (!strcmp(de->d_name, PLAIN_NAME))
            saw_plain = true;
        if (!strncmp(de->d_name, ".elfuse_case_index", 18))
            saw_index = true;
    }
    closedir(d);

    TEST("unmapped token listed as-is");
    EXPECT_TRUE(saw_orphan, "a token with no index row keeps its spelling");

    TEST("host-staged sibling listed");
    EXPECT_TRUE(saw_plain, "a real name with no index row passes through");

    TEST("index file not listed");
    EXPECT_TRUE(!saw_index, "sidecar bookkeeping stays hidden");

    /* Listing it is only correct because it is reachable: lookup falls back to
     * the literal spelling, so the name a listing reports can be opened. These
     * two assertions have to agree, and this is the one that says why.
     */
    TEST("unmapped token reachable by that name");
    struct stat st;
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", STAGE_DIR, ORPHAN_TOKEN);
    EXPECT_TRUE(stat(path, &st) == 0, "listed name must resolve");

    TEST("absent token spelling still ENOENT");
    EXPECT_ERRNO(stat(STAGE_DIR "/.ef_ffffffffffffffff", &st), ENOENT,
                 "the fallback must not invent files");

    SUMMARY("test-sidecar-orphan");
    return fails > 0 ? 1 : 0;
}
