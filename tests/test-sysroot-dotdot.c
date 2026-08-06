/*
 * Sysroot '..' resolution
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A guest resolves '..' against its own root, where Linux clamps it: "/.."
 * names "/" and can never reach the directory holding the guest tree
 * (path_resolution(7)). The sysroot resolvers prefix the sysroot onto the
 * guest path, so a '..' that climbs above the guest root has to be rewritten
 * or it walks out of the tree; every other '..' must survive verbatim, so the
 * host kernel keeps deciding whether the component it pops exists and is a
 * directory.
 *
 * Code under test: proc_resolve_sysroot_path_flags() and
 * proc_resolve_sysroot_create_path() in src/syscall/proc-state.c, and the
 * relative-path containment recheck in src/syscall/path.c. The recipe stages
 * beside.txt in the directory holding the sysroot, so a resolver that fails to
 * clamp has a real file to escape to rather than an absent path that hides the
 * bug.
 *
 * A regression reports ELOOP for an ordinary "/.." path, or reaches
 * beside.txt. Run under --sysroot.
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

int passes = 0, fails = 0;

#define PROBE_PATH "/probe.txt"
#define PROBE_TEXT "guest-probe\n"
#define BESIDE_LEAF "beside.txt"

/* Both names the same object? Compared by identity rather than by spelling,
 * because the whole question is which object a spelling reaches.
 */
static bool same_object(const char *a, const char *b)
{
    struct stat sa, sb;

    return stat(a, &sa) == 0 && stat(b, &sb) == 0 && sa.st_dev == sb.st_dev &&
           sa.st_ino == sb.st_ino;
}

static bool reads_probe(const char *path)
{
    char buf[64];

    return read_file_nul(path, buf, sizeof(buf)) > 0 &&
           !strcmp(buf, PROBE_TEXT);
}

static void section_clamp(void)
{
    TEST("/.. names the guest root");
    EXPECT_TRUE(same_object("/..", "/"), "should be the guest root");

    TEST("a path through /.. resolves at the guest root");
    EXPECT_TRUE(reads_probe("/.." PROBE_PATH), "should read the staged probe");

    TEST("repeated .. cannot climb past the guest root");
    EXPECT_TRUE(reads_probe("/../../.." PROBE_PATH), "should still clamp");

    TEST("lstat clamps the same way as stat");
    {
        struct stat st;
        EXPECT_TRUE(lstat("/..", &st) == 0 && S_ISDIR(st.st_mode),
                    "lstat /.. should see the guest root");
    }

    TEST("the directory holding the sysroot stays invisible");
    EXPECT_ERRNO(open("/../" BESIDE_LEAF, O_RDONLY), ENOENT,
                 "a host sibling must not be reachable through /..");

    TEST("a create through /.. lands inside the sysroot");
    {
        int fd = open("/../made-here.txt", O_CREAT | O_WRONLY, 0644);
        if (fd < 0) {
            FAIL("create through /.. failed");
        } else {
            bool wrote = write_fd_all(fd, "made\n", 5) == 0;
            close(fd);
            EXPECT_TRUE(
                wrote && same_object("/made-here.txt", "/../made-here.txt"),
                "the created file should be the guest's /made-here.txt");
        }
    }

    TEST("a mkdir through /.. lands inside the sysroot");
    {
        struct stat st;
        EXPECT_TRUE((mkdir("/../made-dir", 0755) == 0 || errno == EEXIST) &&
                        stat("/made-dir", &st) == 0 && S_ISDIR(st.st_mode),
                    "the created directory should be the guest's /made-dir");
    }
}

static void section_relative(void)
{
    int root = open("/", O_RDONLY | O_DIRECTORY);

    TEST("open the guest root as a descriptor");
    EXPECT_TRUE(root >= 0, "open / failed");
    if (root < 0)
        return;

    TEST("\"..\" from the root descriptor is the root");
    {
        int fd = openat(root, "..", O_RDONLY | O_DIRECTORY);
        struct stat sa, sb;
        bool same = fd >= 0 && fstat(fd, &sa) == 0 && stat("/", &sb) == 0 &&
                    sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
        if (fd >= 0)
            close(fd);
        EXPECT_TRUE(same, "should be the guest root");
    }

    TEST("a path through \"..\" from the root descriptor resolves");
    {
        int fd = openat(root, ".." PROBE_PATH, O_RDONLY);
        char buf[64];
        bool ok = fd >= 0 && read_fd_all_nul(fd, buf, sizeof(buf)) > 0 &&
                  !strcmp(buf, PROBE_TEXT);
        if (fd >= 0)
            close(fd);
        EXPECT_TRUE(ok, "should read the staged probe");
    }

    TEST("\"..\" from the root descriptor cannot reach a host sibling");
    EXPECT_ERRNO(openat(root, "../" BESIDE_LEAF, O_RDONLY), ENOENT,
                 "the host walk must not escape through the descriptor");

    TEST("a create through \"..\" materializes its missing parents");
    {
        int fd =
            openat(root, "../var/tmp/climb-made.txt", O_CREAT | O_WRONLY, 0644);
        if (fd < 0) {
            FAIL("create through \"..\" with a missing parent failed");
        } else {
            bool wrote = write_fd_all(fd, "made\n", 5) == 0;
            close(fd);
            EXPECT_TRUE(wrote && same_object("/var/tmp/climb-made.txt",
                                             "/../var/tmp/climb-made.txt"),
                        "the file should be the guest's /var/tmp spelling");
        }
    }

    close(root);
}

/* An interior '..' must reach the host verbatim: the resolvers clamp '..'
 * only at the guest root and spell interior ones through untouched, leaving
 * the pop to the kernel's own resolution. What is asserted here is that the
 * pop arrives, not how the kernel type-checks the component it pops.
 */
static void section_interior(void)
{
    TEST("an interior .. still reaches its own directory");
    EXPECT_TRUE(reads_probe("/tmp/../probe.txt"),
                "the probe should be reachable through /tmp/..");
}

int main(void)
{
    printf("test-sysroot-dotdot: sysroot '..' resolution\n");

    section_clamp();
    section_relative();
    section_interior();

    SUMMARY("test-sysroot-dotdot");
    return fails > 0 ? 1 : 0;
}
