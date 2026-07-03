/*
 * Byte-exact lookup regression tests for case-insensitive sysroots
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux path resolution treats names as byte strings: a lookup whose spelling
 * differs from the on-disk entry only by case (or Unicode normalization form)
 * must fail with ENOENT. APFS resolves such lookups case- and
 * normalization-insensitively, so on a case-insensitive sysroot the sidecar
 * walk has to verify the on-disk spelling of every unmapped component instead
 * of trusting the folded openat/fstatat probe. Read-path syscalls (stat, open,
 * access) used to leak the folded match through; mutation syscalls already
 * went through a byte-exact readdir check.
 *
 * The harness (mk/tests.mk) stages inside the sysroot, host-side:
 *   /data/Makefile   ("exact\n")
 *   /data/sub/f.txt  ("sub\n")
 *   /data/caf\xc3\xa9  NFC spelling ("nfc\n")
 * and passes argv[1] = "ci" when the sysroot volume is case-insensitive
 * (sidecar active) or "cs" when it is case-sensitive. The wrong-case probes
 * hold either way; the normalization probes only hold with the sidecar's
 * byte-exact verification, so they are skipped under "cs" (APFS folds
 * normalization even on case-sensitive volumes -- a documented limitation of
 * running without the sidecar).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

#define NFC_NAME "/data/caf\xc3\xa9"  /* e-acute, U+00E9 */
#define NFD_NAME "/data/cafe\xcc\x81" /* e + combining acute, U+0301 */

int passes = 0, fails = 0;

int main(int argc, char **argv)
{
    bool case_insensitive = argc > 1 && !strcmp(argv[1], "ci");
    char buf[64];
    struct stat st;

    printf("test-sysroot-case-exact: byte-exact lookups (%s sysroot)\n",
           case_insensitive ? "case-insensitive" : "case-sensitive");

    TEST("exact spelling resolves");
    if (read_file_nul("/data/Makefile", buf, sizeof(buf)) <= 0 ||
        strcmp(buf, "exact\n"))
        FAIL("exact-case read failed");
    else
        PASS();

    TEST("stat wrong-case final");
    EXPECT_ERRNO(stat("/data/MAKEFILE", &st), ENOENT, "folded stat leaked");

    TEST("open wrong-case final");
    EXPECT_ERRNO(open("/data/makefile", O_RDONLY), ENOENT,
                 "folded open leaked");

    TEST("access wrong-case final");
    EXPECT_ERRNO(access("/data/mAkEfIlE", F_OK), ENOENT,
                 "folded access leaked");

    TEST("stat wrong-case intermediate");
    EXPECT_ERRNO(stat("/DATA/Makefile", &st), ENOENT,
                 "folded intermediate leaked");

    TEST("open wrong-case intermediate");
    EXPECT_ERRNO(open("/data/SUB/f.txt", O_RDONLY), ENOENT,
                 "folded intermediate leaked");

    TEST("unlink wrong-case is ENOENT");
    EXPECT_ERRNO(unlink("/data/mAKEFILE"), ENOENT, "folded unlink leaked");

    TEST("wrong-case unlink kept file");
    if (stat("/data/Makefile", &st) < 0)
        FAIL("exact entry vanished");
    else
        PASS();

    TEST("rename wrong-case source");
    EXPECT_ERRNO(rename("/data/MAKEfile", "/data/moved"), ENOENT,
                 "folded rename leaked");

    /* O_CREAT with a wrong-case spelling must create a second, distinct
     * entry (Linux semantics), not fold onto the existing one.
     */
    TEST("wrong-case O_CREAT|O_EXCL succeeds");
    {
        int fd = open("/data/MAKEFILE", O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd < 0) {
            FAIL("create folded onto existing entry");
        } else {
            if (write_fd_all(fd, "upper\n", 6) < 0)
                FAIL("write failed");
            else
                PASS();
            close(fd);
        }
    }

    TEST("collision pair stays distinct");
    if (read_file_nul("/data/Makefile", buf, sizeof(buf)) <= 0 ||
        strcmp(buf, "exact\n"))
        FAIL("original clobbered");
    else if (read_file_nul("/data/MAKEFILE", buf, sizeof(buf)) <= 0 ||
             strcmp(buf, "upper\n"))
        FAIL("new spelling unreadable");
    else
        PASS();

    if (case_insensitive) {
        TEST("stat NFD form of NFC entry");
        EXPECT_ERRNO(stat(NFD_NAME, &st), ENOENT, "normalization folded");

        TEST("NFC spelling still resolves");
        if (read_file_nul(NFC_NAME, buf, sizeof(buf)) <= 0 ||
            strcmp(buf, "nfc\n"))
            FAIL("NFC read failed");
        else
            PASS();
    }

    SUMMARY("test-sysroot-case-exact");
    return fails > 0 ? 1 : 0;
}
