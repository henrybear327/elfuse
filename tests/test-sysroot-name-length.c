/*
 * Guest filenames at their full length
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux allows a path component of 255 bytes, and a guest is entitled to all
 * of them, including for a name that has to be stored escaped, which is
 * longer on disk than the name it stands for. The volume underneath measures
 * its own limit in UTF-16 code units rather than bytes, which is what leaves
 * room for the escape; this asserts the guest-visible consequence, that no
 * length below the Linux maximum is refused and 256 bytes is.
 *
 * The interesting lengths are the two tier boundaries the encoding has and the
 * Linux maximum. A guest must not be able to tell where a tier changes, so the
 * expectations either side of it are identical.
 *
 * Code under test: the two payload tiers in src/syscall/casefold.c and the
 * length accounting in src/syscall/casefold-walk.c. A regression shows up as
 * ENAMETOOLONG for a name Linux allows (most likely at whichever tier
 * boundary the encoding grew), or as a colliding pair at full length
 * collapsing into one file.
 *
 * Run under --sysroot.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

#define DIR_L "/name-length"
#define GUEST_NAME_MAX 255

/* Everything in this lane lives under one directory and is addressed by name,
 * so the shared helpers are reached through a path built here. Only the
 * composition is local; the I/O is not duplicated.
 */
static int content_is(const char *name, const char *want)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/%s", DIR_L, name);
    return file_content_is(path, want);
}

static bool listed(const char *name)
{
    return dir_contains(DIR_L, name);
}

static void build(char *buf, size_t n, char c)
{
    memset(buf, c, n);
    buf[n] = '\0';
}

/* Build a name of @bytes bytes out of a repeated multi-byte character, so the
 * byte length is what a Linux guest sees while the volume counts characters.
 */
static void build_utf8(char *buf, size_t bytes, const char *unit)
{
    size_t ulen = strlen(unit);
    size_t n = 0;

    while (n + ulen <= bytes) {
        memcpy(buf + n, unit, ulen);
        n += ulen;
    }
    buf[n] = '\0';
}

static int create(const char *name, const char *text)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/%s", DIR_L, name);
    return file_write(path, text);
}

/* One name of a given length: create it, read it back, and require a listing
 * to report the same bytes. @mixed picks whether it needs escaping.
 */
static void check_length(size_t bytes, bool mixed)
{
    char name[GUEST_NAME_MAX + 2];
    char label[64];

    snprintf(label, sizeof(label), "%zu-byte %s name", bytes,
             mixed ? "mixed-case" : "lowercase");
    build(name, bytes, mixed ? 'Q' : 'q');

    TEST(label);
    if (create(name, "x") < 0) {
        FAIL("create");
        return;
    }
    if (content_is(name, "x") < 0) {
        FAIL("reopen");
        return;
    }
    if (!listed(name)) {
        FAIL("listing does not report the name");
        return;
    }
    PASS();
}

/* A colliding pair at a given length. Both members must exist as separate
 * files, which is the case a side-table-free mapping has to earn: the escape
 * is longer than the name, so this is where a length limit would bite.
 */
static void check_pair(size_t bytes)
{
    char lower[GUEST_NAME_MAX + 2];
    char upper[GUEST_NAME_MAX + 2];
    char label[64];

    snprintf(label, sizeof(label), "%zu-byte colliding pair", bytes);
    build(lower, bytes, 'a');
    build(upper, bytes, 'A');

    TEST(label);
    if (create(lower, "lower") < 0 || create(upper, "upper") < 0) {
        FAIL("create both");
        return;
    }
    if (content_is(lower, "lower") < 0 || content_is(upper, "upper") < 0) {
        FAIL("the two names are not separate files");
        return;
    }
    if (!listed(lower) || !listed(upper)) {
        FAIL("both must appear in a listing");
        return;
    }
    PASS();
}

/* openat2(RESOLVE_NO_SYMLINKS) is answered by a walker that resolves the whole
 * path itself and therefore sees host spellings, which for an escaped name run
 * past the guest limit. This is where a walker sized to the guest limit refuses
 * a name Linux allows, with ENAMETOOLONG for a file openat opens fine. Reuses
 * the file check_length left behind.
 */
static void check_openat2(size_t bytes)
{
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_SYMLINKS};
    char name[GUEST_NAME_MAX + 2];
    char path[PATH_MAX];
    char label[64];
    long fd;

    snprintf(label, sizeof(label), "openat2 walks a %zu-byte escaped name",
             bytes);
    build(name, bytes, 'Q');
    snprintf(path, sizeof(path), "%s/%s", DIR_L, name);

    TEST(label);
    errno = 0;
    fd = syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        PASS();
    } else {
        FAIL("a walker refused a name Linux allows");
    }
}

int main(void)
{
    char name[GUEST_NAME_MAX + 2];
    char over[GUEST_NAME_MAX + 3];
    char path[PATH_MAX];

    TEST("fixture mkdir");
    EXPECT_TRUE(mkdir(DIR_L, 0755) == 0 || errno == EEXIST, "mkdir");

    /* A name stored as itself is bounded only by Linux. */
    check_length(1, false);
    check_length(GUEST_NAME_MAX, false);

    /* A name stored escaped is longer on disk than the name it stands for, so
     * these are the lengths that would fail if the escape had a ceiling. The
     * encoding changes shape partway through this range; the guest cannot see
     * where, so the expectations do not either.
     */
    check_length(1, true);
    check_length(124, true);
    check_length(125, true);
    check_length(126, true);
    check_length(127, true);
    check_length(254, true);
    check_length(GUEST_NAME_MAX, true);

    /* The same lengths through the second walker, which must not have a
     * ceiling of its own.
     */
    check_openat2(126);
    check_openat2(GUEST_NAME_MAX);

    /* Both members of a colliding pair, at the maximum. One of them has to be
     * stored under a spelling that is more than twice as long.
     */
    check_pair(8);
    check_pair(125);
    check_pair(126);
    check_pair(GUEST_NAME_MAX);

    /* A multi-byte name at the Linux maximum. The volume would allow three
     * times as many bytes here, but Linux would not, and it is Linux the guest
     * is entitled to.
     */
    build_utf8(name, GUEST_NAME_MAX, "\xe6\x96\x87");
    TEST("255 bytes of CJK");
    EXPECT_TRUE(create(name, "cjk") == 0 && content_is(name, "cjk") == 0 &&
                    listed(name),
                "should round trip");

    {
        char nfc[GUEST_NAME_MAX + 2];
        char nfd[GUEST_NAME_MAX + 2];

        build_utf8(nfc, 250, "caf\xc3\xa9");
        build_utf8(nfd, 250, "cafe\xcc\x81");
        TEST("long normalization twins stay separate");
        EXPECT_TRUE(create(nfc, "nfc") == 0 && create(nfd, "nfd") == 0 &&
                        content_is(nfc, "nfc") == 0 &&
                        content_is(nfd, "nfd") == 0,
                    "two files");
    }

    /* One byte past what Linux allows is refused, and nothing is created. */
    build(over, GUEST_NAME_MAX + 1, 'z');
    snprintf(path, sizeof(path), "%s/%s", DIR_L, over);
    TEST("256-byte name is refused");
    EXPECT_ERRNO(open(path, O_CREAT | O_WRONLY, 0644), ENAMETOOLONG,
                 "should exceed NAME_MAX");
    TEST("256-byte mkdir is refused");
    EXPECT_ERRNO(mkdir(path, 0755), ENAMETOOLONG, "should exceed NAME_MAX");

    SUMMARY("test-sysroot-name-length");
    return fails > 0 ? 1 : 0;
}
