/*
 * A sysroot at the filesystem root
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * "--sysroot /" is degenerate but legal, and it is the one configuration where
 * the host prefix is a single separator. Path arithmetic that assumes the
 * prefix is longer than that produces an empty parent instead of the root, and
 * an empty path fails every containment check, so a create directly below the
 * root reports ELOOP, a diagnosis about symlinks for a path containing none.
 *
 * Code under test: proc_resolve_sysroot_create_path and
 * proc_resolve_sysroot_path_flags in src/syscall/proc-state.c: the parent
 * split off the walk's recorded offsets, and the all-slash guard the
 * containment check needs. A regression shows up as ELOOP where the host's
 * own answer should come through, which sends a caller looking for a link
 * loop that does not exist. With argv[1] set, also path_host_to_guest in
 * src/syscall/path.c: the lane starts inside a directory stored under its
 * escape, so the first getcwd must decode the leaf back to argv[1] rather
 * than hand back the stored bytes.
 *
 * Nothing here writes: the macOS root is read-only, and what is asserted is
 * that the guest is told so rather than being told something untrue. Run under
 * --sysroot /.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define UNWRITABLE "/elfuse-sysroot-root-probe"

int main(int argc, char **argv)
{
    struct stat st;
    int fd;

    printf("test-sysroot-root: sysroot at the filesystem root\n");

    /* The recipe passes the expected leaf only on a folding volume, where a
     * stored escape decodes; on a byte-exact root the stored name means
     * itself and there is nothing to strip wrongly.
     */
    if (argc > 1) {
        char cwd[PATH_MAX];

        TEST("getcwd decodes the stored leaf under --sysroot /");
        if (!getcwd(cwd, sizeof(cwd))) {
            FAIL("getcwd");
        } else {
            const char *leaf = strrchr(cwd, '/');
            bool decoded;

            leaf = leaf ? leaf + 1 : cwd;
            decoded = !strcmp(leaf, argv[1]);
            EXPECT_TRUE(decoded, "cwd leaked the stored spelling");
            if (!decoded)
                fprintf(stderr, "  got %s\n", cwd);
        }
    }

    /* The root is read-only on macOS, so the create must fail, but with the
     * host's reason. ELOOP would mean the path arithmetic broke before the
     * kernel ever saw the request.
     */
    TEST("a create below the root reports the host's own error");
    fd = open(UNWRITABLE, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        close(fd);
        unlink(UNWRITABLE);
        PASS();
    } else {
        EXPECT_TRUE(errno != ELOOP, "ELOOP for a path with no symlink in it");
    }

    TEST("a lookup below the root still resolves");
    EXPECT_TRUE(stat("/etc/hosts", &st) == 0, "stat /etc/hosts");

    TEST("the root itself resolves");
    EXPECT_TRUE(stat("/", &st) == 0 && S_ISDIR(st.st_mode), "stat /");

    /* The nofollow spelling of the same question. The lookup resolver's
     * containment check splits a parent off the resolved path, and with the
     * one-character prefix that parent is the root itself; treating the shape
     * as impossible reported ELOOP for lstat("/"), which no Linux kernel can
     * produce: "/" is a directory, and nofollow only changes the answer for
     * a symlink.
     */
    TEST("the root itself resolves without following");
    EXPECT_TRUE(lstat("/", &st) == 0 && S_ISDIR(st.st_mode), "lstat /");

    TEST("fstatat nofollow agrees");
    EXPECT_TRUE(fstatat(AT_FDCWD, "/", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
                    S_ISDIR(st.st_mode),
                "fstatat AT_SYMLINK_NOFOLLOW /");

    SUMMARY("test-sysroot-root");
    return fails > 0 ? 1 : 0;
}
