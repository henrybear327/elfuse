/*
 * Non-ASCII guest filenames
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A Linux filename is a byte string, and a guest is entitled to use any of
 * them. The volume a sysroot sits on may disagree about which two byte strings
 * are the same name, and it disagrees in ways no simple rule predicts: the
 * German sharp s matches "ss", so a fold can change length; Greek final sigma
 * matches medial sigma, so a fold can depend on position; compatibility
 * mappings apply, so the fi ligature matches "fi". Each pair below is one the
 * volume considers equal, and each must stay two files to the guest.
 *
 * Scripts with no case and no normalization forms (Chinese, Thai, emoji) are
 * here too, because the rule escapes them as well and they have to survive
 * the round trip unchanged.
 *
 * Every name is created by the guest. On a folding sysroot the escape delivers
 * the Linux result for all of them. A case-sensitive APFS sysroot is different:
 * the volume still folds canonical normalization and refuses names that are
 * not well-formed UTF-8, and with case folding absent the escape is inactive,
 * so canonically-equal spellings alias (a write to one clobbers the other) and
 * ill-formed names fail with EILSEQ. That divergence is documented in
 * docs/filenames.md; run with argv[1] "csapfs" the test pins it exactly, so a
 * future change that closes the gap turns these expectations red and updates
 * them deliberately. Case pairs and compatibility-only pairs stay two files
 * there: the volume folds neither.
 *
 * Code under test: src/syscall/casefold.c decides which of these names can be
 * stored as themselves, and src/syscall/casefold-walk.c resolves them. A
 * regression shows up as two names the volume folds together collapsing into
 * one file, or a name whose bytes change on the way back out.
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
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

/* True when the sysroot sits on case-sensitive APFS, where the escape is off
 * but the volume still folds canonical normalization and rejects ill-formed
 * UTF-8. Set by the recipe via argv, like the volume mode in
 * test-sysroot-pathmax: the guest cannot probe this itself, because hiding
 * volume behavior is exactly what the escape does when it is active.
 */
static bool vol_csapfs;

#define DIR_I "/name-i18n"

/* Everything in this lane lives under one directory and is addressed by name,
 * so the shared helpers are reached through a path built here. Only the
 * composition is local; the I/O is not duplicated.
 */
static int write_file(const char *name, const char *text)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/%s", DIR_I, name);
    return file_write(path, text);
}

static int read_back(const char *name, char *buf, size_t bufsz)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/%s", DIR_I, name);
    return read_file_nul(path, buf, bufsz) < 0 ? -1 : 0;
}

static bool in_listing(const char *name)
{
    return dir_contains(DIR_I, name);
}

/* Create one name, read it back, and require it to appear in a listing spelled
 * with exactly the bytes it was created with. @label carries the script so a
 * failure says which one broke.
 */
static void check_roundtrip(const char *label, const char *name)
{
    char got[64];

    TEST(label);
    if (write_file(name, label) < 0) {
        FAIL("create");
        return;
    }
    if (read_back(name, got, sizeof(got)) < 0) {
        FAIL("reopen under the same bytes");
        return;
    }
    if (strcmp(got, label)) {
        FAIL("content came back wrong");
        return;
    }
    if (!in_listing(name)) {
        FAIL("listing does not report the name byte-exactly");
        return;
    }
    PASS();
}

/* Two names the volume matches against each other. They must be two files:
 * distinct content, both listed, and removing one leaving the other.
 */
static void check_pair(const char *label, const char *a, const char *b)
{
    char got[64];

    TEST(label);
    if (write_file(a, "first") < 0 || write_file(b, "second") < 0) {
        FAIL("create both");
        return;
    }
    if (read_back(a, got, sizeof(got)) < 0 || strcmp(got, "first")) {
        FAIL("first name reads the wrong file");
        return;
    }
    if (read_back(b, got, sizeof(got)) < 0 || strcmp(got, "second")) {
        FAIL("second name reads the wrong file");
        return;
    }
    if (!in_listing(a) || !in_listing(b)) {
        FAIL("both spellings must appear in a listing");
        return;
    }
    PASS();
}

/* A canonically-equal pair. On a folding sysroot this is check_pair; on
 * case-sensitive APFS the volume folds the two spellings together with the
 * escape off, so the documented divergence is pinned instead: the second
 * write lands in the first file, both spellings read it, and the listing
 * holds one entry under the first writer's spelling.
 */
static void check_canonical_pair(const char *label,
                                 const char *a,
                                 const char *b)
{
    char got[64];

    if (!vol_csapfs) {
        check_pair(label, a, b);
        return;
    }

    TEST(label);
    if (write_file(a, "first") < 0 || write_file(b, "second") < 0) {
        FAIL("create both");
        return;
    }
    if (read_back(a, got, sizeof(got)) < 0 || strcmp(got, "second") ||
        read_back(b, got, sizeof(got)) < 0 || strcmp(got, "second")) {
        FAIL("spellings did not alias to the second write");
        return;
    }
    if (!in_listing(a) || in_listing(b)) {
        FAIL("listing should hold one entry, spelled as first written");
        return;
    }
    PASS();
}

/* A name that is not well-formed UTF-8. On a folding sysroot the escape
 * stores it; on case-sensitive APFS the volume refuses it and the guest sees
 * EILSEQ, which is the divergence to pin.
 */
static void check_invalid_utf8(const char *label, const char *name)
{
    if (!vol_csapfs) {
        check_roundtrip(label, name);
        return;
    }

    TEST(label);
    errno = 0;
    if (write_file(name, "x") == 0 || errno != EILSEQ)
        FAIL("an ill-formed name should be refused with EILSEQ");
    else
        PASS();
}

int main(int argc, char **argv)
{
    vol_csapfs = argc > 1 && !strcmp(argv[1], "csapfs");

    TEST("fixture mkdir");
    EXPECT_TRUE(mkdir(DIR_I, 0755) == 0 || errno == EEXIST, "mkdir");

    /* Scripts with no case and no normalization forms. Nothing here collides;
     * the rule escapes them anyway, so they exercise the round trip.
     */
    check_roundtrip("chinese simplified", "\xe6\x96\x87\xe6\xa1\xa3.txt");
    check_roundtrip("chinese traditional", "\xe6\xaa\x94\xe6\xa1\x88.txt");
    check_roundtrip("thai", "\xe0\xb9\x84\xe0\xb8\x97\xe0\xb8\xa2");
    check_roundtrip("arabic", "\xd9\x85\xd9\x84\xd9\x81");
    check_roundtrip("emoji", "\xf0\x9f\x9a\x80.log");
    check_roundtrip("emoji zwj sequence",
                    "\xf0\x9f\x91\xa9\xe2\x80\x8d\xf0\x9f\x92\xbb");
    check_roundtrip("mixed script", "a-\xe6\x96\x87-z");

    /* Case folding beyond ASCII. */
    check_pair("accented latin case", "\xc3\x89t\xc3\xa9", "\xc3\xa9t\xc3\xa9");
    check_pair("cyrillic case", "\xd0\x94\xd0\x90", "\xd0\xb4\xd0\xb0");
    check_pair("greek sigma case", "\xce\xa3o\xcf\x82", "\xcf\x83o\xcf\x82");
    check_pair("greek final vs medial sigma", "\xcf\x83q\xcf\x82",
               "\xcf\x83q\xcf\x83");
    check_pair("german sharp s vs ss",
               "stra\xc3\x9f"
               "e",
               "strasse");
    check_pair("deseret, cased beyond the BMP", "\xf0\x90\x90\x80y",
               "\xf0\x90\x90\xa8y");

    /* Normalization. The canonical pairs (composed against decomposed,
     * singletons included) go through check_canonical_pair, because
     * case-sensitive APFS folds canonical equivalence even with case folding
     * off. The fi ligature is compatibility-only and stays distinct there.
     */
    check_canonical_pair("french NFC vs NFD", "caf\xc3\xa9", "cafe\xcc\x81");
    check_canonical_pair("german umlaut NFC vs NFD",
                         "\xc3\xbc"
                         "ber",
                         "u\xcc\x88"
                         "ber");
    check_canonical_pair("japanese kana NFC vs NFD", "\xe3\x81\x8c",
                         "\xe3\x81\x8b\xe3\x82\x99");
    check_canonical_pair("korean hangul NFC vs jamo", "\xed\x95\x9c",
                         "\xe1\x84\x92\xe1\x85\xa1\xe1\x86\xab");
    check_canonical_pair("vietnamese, two combining marks",
                         "\xe1\xbb\x87"
                         "d",
                         "e\xcc\xa3\xcc\x82"
                         "d");
    check_canonical_pair("devanagari NFC vs NFD",
                         "\xe0\xa4\xa9"
                         "e",
                         "\xe0\xa4\xa8\xe0\xa4\xbc"
                         "e");
    check_canonical_pair("ohm sign vs omega",
                         "\xe2\x84\xa6"
                         "a",
                         "\xce\xa9"
                         "a");
    check_canonical_pair("angstrom sign vs A-ring",
                         "\xe2\x84\xab"
                         "c",
                         "\xc3\x85"
                         "c");
    check_pair("fi ligature vs fi",
               "\xef\xac\x81"
               "b",
               "fib");
    check_canonical_pair("hebrew presentation form",
                         "\xef\xac\xae"
                         "f",
                         "\xd7\x90\xd6\xb7"
                         "f");

    /* Turkish dotless i is a distinct letter, not a case variant of ASCII i.
     * The rule escapes it because it is non-ASCII, and "id" stays literal, so
     * they cannot interfere however the volume treats them.
     */
    check_pair("turkish dotless i vs ascii i",
               "\xc4\xb1"
               "d",
               "id");

    /* Names that are not valid UTF-8 at all. The volume refuses to store them
     * as themselves, so escaping is the only way they can exist.
     */
    check_invalid_utf8("invalid utf-8, high bytes",
                       "bad\xff\xfe"
                       "name");
    check_invalid_utf8("invalid utf-8, lone continuation",
                       "lone\x80"
                       "byte");
    check_invalid_utf8("invalid utf-8, truncated sequence", "trunc\xe3\x81");
    check_invalid_utf8("invalid utf-8, surrogate",
                       "sur\xed\xa0\x80"
                       "rogate");

    /* Everything created above must still be reachable, so the escapes have
     * not collided with each other.
     */
    TEST("every name is still readable");
    {
        /* The ill-formed name exists only where the escape stored it; the
         * caf\xc3\xa9 spellings read the same file on csapfs and different
         * ones elsewhere, but both must resolve either way.
         */
        char got[64];
        EXPECT_TRUE(
            read_back("\xe6\x96\x87\xe6\xa1\xa3.txt", got, sizeof(got)) == 0 &&
                read_back("caf\xc3\xa9", got, sizeof(got)) == 0 &&
                read_back("cafe\xcc\x81", got, sizeof(got)) == 0 &&
                (vol_csapfs || read_back("bad\xff\xfe"
                                         "name",
                                         got, sizeof(got)) == 0),
            "a name became unreachable");
    }

    SUMMARY("test-sysroot-name-i18n");
    return fails > 0 ? 1 : 0;
}
