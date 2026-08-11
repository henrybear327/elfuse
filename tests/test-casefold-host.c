/*
 * Native-host unit test for the case-folding filename codec
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Two arms. The pure arm drives the codec over a table of names (boundaries,
 * malformed escapes, every ill-formed UTF-8 shape, and an internationalization
 * corpus) and needs nothing but the CPU. The filesystem arm needs a directory
 * and asserts the three things the design assumes about the volume underneath:
 * that the payload alphabet cannot fold, that everything the encoder emits can
 * actually be created, and that a byte-exact spelling probe works at all.
 *
 * The filesystem arm is why a change in a future macOS release surfaces here
 * rather than as a mysterious guest failure. Point it at any directory to see
 * how a different volume behaves:
 *
 *     build/test-casefold-host /Volumes/case-sensitive-image
 *
 * Code under test: src/syscall/casefold.c. A regression shows up as a guest
 * name that comes back as a different name, two distinct names sharing one
 * encoding, or a name elfuse emits that the volume then refuses to create.
 * Each of those would surface inside a guest much later as a missing or a
 * wrong file.
 *
 * Native macOS binary; no HVF entitlement needed.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <unistd.h>

#include "casefold-vectors.h"
#include "host-test-util.h"
#include "syscall/casefold.h"

/* Print a name so a failure is diagnosable when the bytes are not printable. */
static void dump(const char *label, const char *s)
{
    fprintf(stderr, "  %s = \"", label);
    for (const unsigned char *p = (const unsigned char *) s; *p; p++) {
        if (*p >= 0x20 && *p < 0x7F)
            fputc(*p, stderr);
        else
            fprintf(stderr, "\\x%02x", *p);
    }
    fprintf(stderr, "\"\n");
}

/* ---------------------------------------------------------------- pure arm */

/* Escape, confirm the result is recognized, decode, and require the original
 * bytes back. Also holds the encoded form to the host's per-name budget, since
 * an encoding that does not fit is useless however well it round-trips.
 */
static void check_roundtrip(const char *label, const char *guest)
{
    char enc[CASEFOLD_HOST_NAME_MAX + 1];
    char dec[CASEFOLD_GUEST_NAME_MAX + 1];
    size_t units;

    if (casefold_escape(guest, enc, sizeof(enc)) < 0) {
        host_fail(label, "escape failed");
        dump("guest", guest);
        return;
    }
    if (!casefold_is_escaped(enc)) {
        host_fail(label, "encoded form is not recognized as an escape");
        dump("encoded", enc);
        return;
    }
    units = casefold_utf16_units(enc);
    if (units == 0 || units > CASEFOLD_UNIT_MAX) {
        host_fail(label, "encoded form exceeds the host per-name budget");
        fprintf(stderr, "  units = %zu\n", units);
        return;
    }
    if (casefold_to_guest(enc, dec, sizeof(dec)) < 0) {
        host_fail(label, "decode failed");
        dump("encoded", enc);
        return;
    }
    if (strcmp(dec, guest)) {
        host_fail(label, "round trip changed the name");
        dump("guest", guest);
        dump("decoded", dec);
        return;
    }
    host_ok();
}

static void check_not_escaped(const char *label, const char *host)
{
    char out[CASEFOLD_HOST_NAME_MAX + 1];

    if (casefold_is_escaped(host)) {
        host_fail(label, "malformed escape was accepted");
        dump("host", host);
        return;
    }
    /* An unrecognized shape must pass through as itself, or a listing would
     * report a name the guest cannot open.
     */
    if (casefold_to_guest(host, out, sizeof(out)) < 0 || strcmp(out, host)) {
        host_fail(label, "unrecognized name did not pass through unchanged");
        return;
    }
    host_ok();
}

static void check_needs_escape(const char *label, const char *name, bool want)
{
    if (casefold_needs_escape(name) != want) {
        host_fail(label,
                  want ? "should need escaping" : "should not need escaping");
        dump("name", name);
        return;
    }
    host_ok();
}

/* casefold_utf16_units spends no budget on a name that is not well-formed
 * UTF-8, which is the observable form of that judgment: such a name cannot be
 * stored literally and is going to be escaped instead. Every case below passes
 * a non-empty name, so a nonzero count means well-formed.
 */
static void check_utf8(const char *label, const char *s, bool want)
{
    if ((casefold_utf16_units(s) > 0) != want) {
        host_fail(label,
                  want ? "should be valid UTF-8" : "should be invalid UTF-8");
        dump("name", s);
        return;
    }
    host_ok();
}

static void check_units(const char *label, const char *s, size_t want)
{
    size_t got = casefold_utf16_units(s);

    if (got != want) {
        host_fail(label, "wrong UTF-16 unit count");
        fprintf(stderr, "  got %zu, expected %zu\n", got, want);
        return;
    }
    host_ok();
}

static void fill(char *buf, size_t n, char c)
{
    memset(buf, c, n);
    buf[n] = '\0';
}

/* The frozen table is the one check that fails when the format moves: every
 * other section reads its expectations back through the codec, so a
 * self-consistent format change keeps them green while orphaning every
 * sysroot already on disk. Each escaped row is asserted byte-exact in both
 * directions; a red row here means the on-disk format broke, and the remedy
 * is a format migration, not a new literal.
 */
static void section_golden(void)
{
    char host[CASEFOLD_HOST_NAME_MAX + 1];
    char guest[CASEFOLD_GUEST_NAME_MAX + 1];
    size_t n = sizeof(casefold_vectors) / sizeof(casefold_vectors[0]);

    for (size_t i = 0; i < n; i++) {
        const struct casefold_vector *v = &casefold_vectors[i];
        bool literal = !strcmp(v->guest, v->host);

        if (casefold_needs_escape(v->guest) == literal) {
            host_fail(v->label, literal ? "should be stored literally"
                                        : "should be escaped");
            dump("guest", v->guest);
            continue;
        }
        if (!literal) {
            if (casefold_escape(v->guest, host, sizeof(host)) < 0) {
                host_fail(v->label, "escape failed");
                dump("guest", v->guest);
                continue;
            }
            if (strcmp(host, v->host)) {
                host_fail(v->label,
                          "on-disk spelling moved off the frozen bytes");
                dump("expected", v->host);
                dump("got", host);
                continue;
            }
            if (!casefold_is_escaped(v->host)) {
                host_fail(v->label,
                          "frozen spelling not recognized as an escape");
                continue;
            }
        }
        if (casefold_to_guest(v->host, guest, sizeof(guest)) < 0 ||
            strcmp(guest, v->guest)) {
            host_fail(v->label,
                      "frozen spelling did not decode to the guest name");
            dump("host", v->host);
            dump("decoded", guest);
            continue;
        }
        host_ok();
    }

    /* The long-tier budget arithmetic, pinned on the frozen strings: symbols
     * are BMP code points, one UTF-16 unit each, on top of the four ASCII
     * prefix units.
     */
    check_units("long-tier min units", ".ef=" CFV_LEN126 CFV_PAIR42, 89);
    check_units("linux name max units", ".ef=" CFV_LEN255 CFV_PAIR85, 175);
}

static void section_boundaries(void)
{
    char name[CASEFOLD_GUEST_NAME_MAX + 1];
    char enc[CASEFOLD_HOST_NAME_MAX + 1];

    /* Both sides of the tier boundary, and the largest name Linux can express.
     * The long tier exists precisely so the last of these works.
     */
    fill(name, CASEFOLD_HEX_MAX, 'x');
    check_roundtrip("hex tier at its maximum", name);
    fill(name, CASEFOLD_HEX_MAX + 1, 'x');
    check_roundtrip("symbol tier at its minimum", name);
    fill(name, CASEFOLD_GUEST_NAME_MAX, 'x');
    check_roundtrip("guest NAME_MAX", name);
    fill(name, CASEFOLD_GUEST_NAME_MAX, 'X');
    check_roundtrip("guest NAME_MAX, all uppercase", name);
    fill(name, 1, 'q');
    check_roundtrip("single byte", name);

    /* The exact worst case, not just "within budget". docs/filenames.md quotes
     * these two numbers as the headroom argument for why no guest name can ever
     * be refused for length, and prose drifts from code silently; asserting
     * them keeps the claim measured. 255 bytes is the largest name Linux can
     * express, so nothing gets closer than this.
     */
    fill(name, CASEFOLD_GUEST_NAME_MAX, 'X');
    if (casefold_escape(name, enc, sizeof(enc)) == 0 &&
        casefold_utf16_units(enc) == 175 && CASEFOLD_UNIT_MAX - 175 == 80)
        host_ok();
    else
        host_fail("worst-case escape costs 175 of 255 units",
                  "the longest guest name no longer costs 175 units");

    /* The tier is picked by length alone, so a short name is never spelled with
     * symbols and a long one never with hex. That is half of what makes each
     * name have exactly one encoding.
     */
    fill(name, CASEFOLD_HEX_MAX, 'x');
    if (casefold_escape(name, enc, sizeof(enc)) == 0 &&
        (unsigned char) enc[CASEFOLD_PREFIX_LEN] < 0x80)
        host_ok();
    else
        host_fail("hex tier uses hex", "short name did not use the hex tier");
    fill(name, CASEFOLD_HEX_MAX + 1, 'x');
    if (casefold_escape(name, enc, sizeof(enc)) == 0 &&
        (unsigned char) enc[CASEFOLD_PREFIX_LEN] >= 0x80)
        host_ok();
    else
        host_fail("symbol tier uses symbols",
                  "long name did not use the symbol tier");

    /* "." and ".." name no entry, so no escape can stand for one. Rejecting
     * them keeps every name the codec accepts one that has a slot to live in;
     * accepting them would produce a spelling that decodes to something no
     * directory can hold.
     */
    if (casefold_escape(".", enc, sizeof(enc)) < 0 && errno == EINVAL)
        host_ok();
    else
        host_fail("dot is refused", "\".\" was escaped");
    if (casefold_escape("..", enc, sizeof(enc)) < 0 && errno == EINVAL)
        host_ok();
    else
        host_fail("dotdot is refused", "\"..\" was escaped");

    /* A guest name over NAME_MAX cannot reach a syscall, but the codec must
     * reject it rather than truncate.
     */
    fill(name, CASEFOLD_GUEST_NAME_MAX, 'x');
    char over[CASEFOLD_GUEST_NAME_MAX + 2];
    memset(over, 'x', sizeof(over) - 1);
    over[sizeof(over) - 1] = '\0';
    if (casefold_escape(over, enc, sizeof(enc)) < 0 && errno == EINVAL)
        host_ok();
    else
        host_fail("over-long guest name", "should be rejected with EINVAL");

    /* A caller buffer too small is ENAMETOOLONG, which is distinct from "this
     * name has no representation"; the latter cannot happen.
     */
    fill(name, 8, 'x');
    if (casefold_escape(name, enc, 4) < 0 && errno == ENAMETOOLONG)
        host_ok();
    else
        host_fail("short output buffer",
                  "should be rejected with ENAMETOOLONG");

    /* '/' separates components and so never appears inside one. Encoding it
     * would produce a name no directory could hold, so it is refused outright
     * rather than escaped.
     */
    if (casefold_escape("a/z", enc, sizeof(enc)) < 0 && errno == EINVAL)
        host_ok();
    else
        host_fail("component containing a slash",
                  "should be rejected with EINVAL");
    if (casefold_escape("", enc, sizeof(enc)) < 0 && errno == EINVAL)
        host_ok();
    else
        host_fail("empty component", "should be rejected with EINVAL");
}

static void section_shapes(void)
{
    /* Everything here is a name a host tool could stage. None is a well-formed
     * escape, so each must mean itself.
     */
    check_not_escaped("bare prefix", ".ef=");
    check_not_escaped("prefix truncated", ".ef");
    check_not_escaped("odd hex length", ".ef=464f4");
    check_not_escaped("uppercase hex", ".ef=464F4F");
    check_not_escaped("non-hex tail", ".ef=zzzz");
    check_not_escaped("hex with trailing junk", ".ef=464f4fq");
    check_not_escaped("prefix not at the start", "a.ef=464f4f");
    check_not_escaped("wrong separator", ".ef_464f4f");
    check_not_escaped("decodes to a slash", ".ef=2f");
    check_not_escaped("decodes to dot", ".ef=2e");
    check_not_escaped("decodes to dotdot", ".ef=2e2e");
    check_not_escaped("decodes to an embedded NUL", ".ef=610062");
    check_not_escaped("empty decode", ".ef=");
    /* U+4E00 is a payload symbol, but a lone one is not a valid frame: the
     * first symbol carries a length, and 0 is not a legal name length.
     */
    check_not_escaped("single payload symbol", ".ef=\xe4\xb8\x80");
    /* U+3042 HIRAGANA A sits outside the payload block. */
    check_not_escaped("symbol outside the block", ".ef=\xe3\x81\x82");

    /* A guest name shaped like an escape is escaped itself, so reading it back
     * yields the name and not whatever it would have decoded to.
     */
    check_needs_escape("escape-shaped guest name", ".ef=464f4f", true);
    check_roundtrip("escape-shaped guest name round trip", ".ef=464f4f");

    /* Only the escape prefix is special. Deciding a spelling from the name
     * alone leaves the sysroot no bookkeeping file to hide, so no other name is
     * reserved and a leading dot buys nothing. Pinned because an earlier scheme
     * did reserve a name, and a rule that quietly claims one again would make
     * the guest unable to create a file Linux allows.
     */
    check_needs_escape("a dotfile is not special", ".elfuse_case_index", false);
    check_roundtrip("a dotfile round trips", ".elfuse_case_index");
    check_needs_escape("a bare dotfile is not special", ".hidden", false);

    char enc[CASEFOLD_HOST_NAME_MAX + 1];
    char dec[CASEFOLD_GUEST_NAME_MAX + 1];
    if (casefold_escape(".ef=464f4f", enc, sizeof(enc)) == 0 &&
        casefold_to_guest(enc, dec, sizeof(dec)) == 0 &&
        !strcmp(dec, ".ef=464f4f") && strcmp(dec, "FOO"))
        host_ok();
    else
        host_fail("escape-shaped name is not confused with FOO",
                  "decoded to the wrong name");

    /* Which names must be escaped at all. Lowercase ASCII is the fixed point
     * that can be stored literally; everything else cannot.
     */
    check_needs_escape("lowercase ascii", "config.json", false);
    check_needs_escape("digits and punctuation", "a-b_c.1~2", false);
    check_needs_escape("one uppercase", "Makefile", true);
    check_needs_escape("non-ascii", "caf\xc3\xa9", true);
    check_needs_escape("invalid utf-8", "bad\xff", true);
}

static void section_utf8(void)
{
    check_utf8("ascii", "plain", true);
    check_utf8("two-byte", "caf\xc3\xa9", true);
    check_utf8("three-byte", "\xe6\x96\x87", true);
    check_utf8("four-byte", "\xf0\x9f\x9a\x80", true);

    check_utf8("lone continuation", "a\x80", false);
    check_utf8("truncated two-byte", "a\xc3", false);
    check_utf8("truncated three-byte", "a\xe3\x81", false);
    check_utf8("truncated four-byte", "a\xf0\x9f\x9a", false);
    check_utf8("overlong two-byte", "a\xc0\xaf", false);
    check_utf8("overlong three-byte", "a\xe0\x80\xaf", false);
    check_utf8("surrogate low", "a\xed\xa0\x80", false);
    check_utf8("surrogate high", "a\xed\xbf\xbf", false);
    check_utf8("above U+10FFFF", "a\xf4\x90\x80\x80", false);
    check_utf8("five-byte form", "a\xf8\x88\x80\x80\x80", false);
    check_utf8("0xfe", "a\xfe", false);
    check_utf8("0xff", "a\xff", false);

    /* The host counts UTF-16 units, so a code point above the BMP costs two.
     * Getting this wrong is the likeliest way to emit a name the volume
     * refuses, which is why the filesystem arm cross-checks it.
     */
    check_units("ascii units", "abcd", 4);
    check_units("two-byte units", "caf\xc3\xa9", 4);
    check_units("three-byte units", "\xe6\x96\x87\xe6\xa1\xa3", 2);
    check_units("surrogate pair units", "\xf0\x9f\x9a\x80", 2);
    check_units("mixed units", "a\xe6\x96\x87\xf0\x9f\x9a\x80", 4);
    check_units("invalid utf-8 has no unit count", "a\xff", 0);
}

/* Names drawn from the measured behavior of the volume: every one of these
 * pairs matches the same on-disk entry, so each member must encode distinctly.
 */
static const char *const i18n_corpus[] = {
    "Foo",
    "foo",
    "FOO",
    "caf\xc3\xa9",  /* NFC e-acute */
    "cafe\xcc\x81", /* NFD e + combining acute */
    "\xc3\x89t\xc3\xa9",
    "\xc3\xa9t\xc3\xa9",
    "\xc3\xbc"
    "ber",
    "u\xcc\x88"
    "ber",
    "stra\xc3\x9f"
    "e",
    "strasse",
    "STRASSE",
    "\xcf\x83o\xcf\x82",
    "\xcf\x83o\xcf\x83",
    "\xce\xa3o\xcf\x82",
    "\xd0\x94\xd0\x90",
    "\xd0\xb4\xd0\xb0",
    "\xc4\xb1"
    "d",
    "id",
    "\xc4\xb0"
    "d",
    "\xe6\x96\x87\xe6\xa1\xa3.txt",
    "\xe6\x96\x87\xe4\xbb\xb6.txt",
    "\xe3\x81\x8c",
    "\xe3\x81\x8b\xe3\x82\x99",
    "\xed\x95\x9c",
    "\xe1\x84\x92\xe1\x85\xa1\xe1\x86\xab",
    "\xe2\x84\xa6"
    "a",
    "\xce\xa9"
    "a",
    "\xe2\x84\xab"
    "c",
    "\xc3\x85"
    "c",
    "\xef\xac\x81"
    "b",
    "fib",
    "\xe1\xbb\x87"
    "d",
    "e\xcc\xa3\xcc\x82"
    "d",
    "\xe0\xa4\xa9"
    "e",
    "\xe0\xa4\xa8\xe0\xa4\xbc"
    "e",
    "\xf0\x9f\x9a\x80",
    "\xe2\xad\x90",
    "\xf0\x90\x90\x80"
    "y",
    "\xf0\x90\x90\xa8"
    "y",
    "\xe1\x8e\xa0"
    "x",
    "\xe1\x8f\xb8"
    "x",
};

static void section_i18n(void)
{
    size_t n = sizeof(i18n_corpus) / sizeof(i18n_corpus[0]);

    for (size_t i = 0; i < n; i++) {
        if (casefold_needs_escape(i18n_corpus[i]))
            check_roundtrip("i18n round trip", i18n_corpus[i]);
        else
            host_ok(); /* fold-stable names are stored literally, nothing to
                        * encode
                        */
    }

    /* Distinct names must encode distinctly, or two files would share a slot.
     * Quadratic over a few dozen entries is free and catches an encoder that
     * loses information.
     */
    for (size_t i = 0; i < n; i++) {
        char a[CASEFOLD_HOST_NAME_MAX + 1];
        if (!casefold_needs_escape(i18n_corpus[i]))
            continue;
        /* An encoder that refused these names would skip every comparison and
         * reach the host_ok() below having proved nothing, so a refusal is the
         * failure rather than a reason to move on.
         */
        if (casefold_escape(i18n_corpus[i], a, sizeof(a)) < 0) {
            host_fail("distinct names encode distinctly", "escape failed");
            dump("name", i18n_corpus[i]);
            return;
        }
        for (size_t j = i + 1; j < n; j++) {
            char b[CASEFOLD_HOST_NAME_MAX + 1];
            if (!strcmp(i18n_corpus[i], i18n_corpus[j]))
                continue;
            if (!casefold_needs_escape(i18n_corpus[j]))
                continue;
            if (casefold_escape(i18n_corpus[j], b, sizeof(b)) < 0) {
                host_fail("distinct names encode distinctly", "escape failed");
                dump("name", i18n_corpus[j]);
                return;
            }
            if (!strcmp(a, b)) {
                host_fail("distinct names encode distinctly",
                          "two names share an encoding");
                dump("first", i18n_corpus[i]);
                dump("second", i18n_corpus[j]);
                return;
            }
        }
    }
    host_ok();
}

/* ---------------------------------------------------------- filesystem arm */

static int create_in(const char *dir, const char *name)
{
    char path[8192];
    int fd;

    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int) sizeof(path))
        return -ENAMETOOLONG;
    fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0)
        return -errno;
    close(fd);
    return 0;
}

/* Every payload symbol must be distinct from every other after the volume has
 * had its way with them. Creating all 4096 in one directory proves it outright:
 * any fold between two of them shows up as EEXIST.
 */
static void section_alphabet(const char *root)
{
    char dir[4096];
    int created = 0;

    snprintf(dir, sizeof(dir), "%s/alphabet", root);
    if (mkdir(dir, 0755) < 0) {
        host_fail("alphabet directory", strerror(errno));
        return;
    }
    for (unsigned v = 0; v < 4096; v++) {
        const unsigned cp = 0x4E00 + v; /* CASEFOLD_SYM_BASE in casefold.c */
        char name[8];
        int len = utf8_put(name, cp);
        int rc;

        name[len] = '\0';
        rc = create_in(dir, name);
        if (rc < 0) {
            host_fail("payload alphabet is fold-free", strerror(-rc));
            fprintf(stderr, "  symbol %u (U+%04X)\n", v, cp);
            return;
        }
        created++;
    }
    if (created == 4096)
        host_ok();

    int seen = 0;
    DIR *d = opendir(dir);
    struct dirent *de;
    while (d && (de = readdir(d))) {
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, ".."))
            seen++;
    }
    if (d)
        closedir(d);
    if (seen == 4096) {
        host_ok();
    } else {
        host_fail("payload alphabet survives a listing", "wrong entry count");
        fprintf(stderr, "  listed %d of 4096\n", seen);
    }
}

/* Nothing the encoder emits may be rejected by the volume. This is the backstop
 * for the unit accounting: if the budget arithmetic is wrong anywhere, a create
 * fails here instead of failing inside a guest much later.
 */
static void section_accept(const char *root)
{
    char dir[4096];
    unsigned seed = 0x9E3779B9u;
    bool bad = false;

    snprintf(dir, sizeof(dir), "%s/accept", root);
    if (mkdir(dir, 0755) < 0) {
        host_fail("acceptance directory", strerror(errno));
        return;
    }

    /* Every byte value, alone and surrounded, then the i18n corpus, then a
     * deterministic sweep of every length. The seed is fixed so a failure is
     * reproducible; a random one would report a case nobody could re-run.
     */
    for (unsigned b = 1; b < 256 && !bad; b++) {
        char one[2] = {(char) b, '\0'};
        char three[4] = {'a', (char) b, 'z', '\0'};
        const char *names[2] = {one, three};

        /* '/' separates components and so never appears inside one; the codec
         * rejects it rather than encode a name no directory could hold.
         */
        if (b == '/')
            continue;

        for (int k = 0; k < 2; k++) {
            char host[CASEFOLD_HOST_NAME_MAX + 1];
            int rc;

            /* "." and ".." navigate rather than name an entry, so no directory
             * can hold one and the codec refuses them. Only the single-byte
             * form can produce one here; "a.z" is an ordinary name and stays.
             */
            if (!strcmp(names[k], ".") || !strcmp(names[k], ".."))
                continue;

            if (casefold_needs_escape(names[k])) {
                if (casefold_escape(names[k], host, sizeof(host)) < 0) {
                    host_fail("encoder accepts every byte", "escape failed");
                    dump("name", names[k]);
                    bad = true;
                    break;
                }
            } else {
                snprintf(host, sizeof(host), "%s", names[k]);
            }
            /* EEXIST is a failure, not a tolerated outcome. Every name in
             * this sweep is distinct, so a second create landing on an entry
             * that is already there means two guest names reached one slot,
             * precisely the collision the encoding exists to prevent, and
             * exactly what tolerating EEXIST would hide.
             */
            rc = create_in(dir, host);
            if (rc < 0) {
                host_fail("encoder output is creatable",
                          rc == -EEXIST ? "two names share one entry"
                                        : strerror(-rc));
                dump("guest", names[k]);
                dump("host", host);
                bad = true;
                break;
            }
        }
    }

    for (size_t i = 0; i < sizeof(i18n_corpus) / sizeof(i18n_corpus[0]) && !bad;
         i++) {
        char host[CASEFOLD_HOST_NAME_MAX + 1];
        int rc;

        if (casefold_needs_escape(i18n_corpus[i])) {
            if (casefold_escape(i18n_corpus[i], host, sizeof(host)) < 0) {
                host_fail("encoder accepts the i18n corpus", "escape failed");
                bad = true;
                break;
            }
        } else {
            snprintf(host, sizeof(host), "%s", i18n_corpus[i]);
        }
        rc = create_in(dir, host);
        if (rc < 0) {
            host_fail(
                "i18n encoder output is creatable",
                rc == -EEXIST ? "two names share one entry" : strerror(-rc));
            dump("guest", i18n_corpus[i]);
            dump("host", host);
            bad = true;
        }
    }

    for (size_t n = 1; n <= CASEFOLD_GUEST_NAME_MAX && !bad; n++) {
        char guest[CASEFOLD_GUEST_NAME_MAX + 1];
        char host[CASEFOLD_HOST_NAME_MAX + 1];
        int rc;

        for (size_t i = 0; i < n; i++) {
            seed = seed * 1103515245u + 12345u;
            /* Any byte but NUL and '/', which no filename may contain. */
            unsigned char c = (unsigned char) (seed >> 16);
            if (c == 0 || c == '/')
                c = 'a';
            guest[i] = (char) c;
        }
        guest[n] = '\0';

        if (casefold_needs_escape(guest)) {
            if (casefold_escape(guest, host, sizeof(host)) < 0) {
                host_fail("encoder handles every length", "escape failed");
                fprintf(stderr, "  length %zu\n", n);
                bad = true;
                break;
            }
        } else {
            snprintf(host, sizeof(host), "%s", guest);
        }
        rc = create_in(dir, host);
        if (rc < 0 && rc != -EEXIST) {
            host_fail("encoder output is creatable at every length",
                      strerror(-rc));
            fprintf(stderr, "  length %zu\n", n);
            dump("host", host);
            bad = true;
        }
    }

    if (!bad)
        host_ok();
}

/* The three volume behaviors the resolver is built on. If a macOS release
 * changes any of them the design needs revisiting, so each gets its own
 * message rather than a generic assertion failure.
 */
static void section_volume(const char *root)
{
    char dir[4096];
    char path[8192];
    char real[PATH_MAX];
    const char *spelling;

    snprintf(dir, sizeof(dir), "%s/volume", root);
    if (mkdir(dir, 0755) < 0) {
        host_fail("volume directory", strerror(errno));
        return;
    }
    if (create_in(dir, "Mixed.Case") < 0) {
        host_fail("volume fixture", strerror(errno));
        return;
    }

    spelling = disk_name(dir, "Mixed.Case");
    if (spelling && !strcmp(spelling, "Mixed.Case"))
        host_ok();
    else
        host_fail("getattrlistat reports the on-disk spelling",
                  "probe did not return the name as stored");

    /* On a folding volume the probe is what separates "absent" from "present
     * under another spelling"; on a case-sensitive one the wrong case is simply
     * absent. Both answers are correct, and neither is "exists as spelled".
     */
    spelling = disk_name(dir, "mixed.case");
    if (!spelling || strcmp(spelling, "mixed.case"))
        host_ok();
    else
        host_fail("a wrong-case spelling is never reported as exact",
                  "probe accepted a folded spelling");

    snprintf(path, sizeof(path), "%s/mixed.case", dir);
    if (realpath(path, real)) {
        const char *base = strrchr(real, '/');
        if (base && !strcmp(base + 1, "Mixed.Case"))
            host_ok();
        else
            host_fail("realpath returns the true on-disk case", real);
    } else {
        /* A case-sensitive volume has no such entry at all, which is fine. */
        host_ok();
    }

    /* The per-name budget is counted in UTF-16 units, not bytes: this is what
     * lets the symbol tier hold a full-length guest name.
     */
    char wide[1024];
    int len = 0;
    for (int i = 0; i < CASEFOLD_UNIT_MAX; i++)
        len += utf8_put(wide + len, 0x6587);
    wide[len] = '\0';
    if (create_in(dir, wide) == 0)
        host_ok();
    else
        host_fail("a 255-unit BMP name is creatable",
                  "the per-name limit is not counted in UTF-16 units");

    len = 0;
    for (int i = 0; i < CASEFOLD_UNIT_MAX + 1; i++)
        len += utf8_put(wide + len, 0x6587);
    wide[len] = '\0';
    if (create_in(dir, wide) == -ENAMETOOLONG)
        host_ok();
    else
        host_fail("a 256-unit name is refused",
                  "the per-name limit is not 255 UTF-16 units");

    /* The worst case the encoder can produce, created for real. */
    char guest[CASEFOLD_GUEST_NAME_MAX + 1];
    char host[CASEFOLD_HOST_NAME_MAX + 1];
    fill(guest, CASEFOLD_GUEST_NAME_MAX, 'Q');
    if (casefold_escape(guest, host, sizeof(host)) == 0 &&
        create_in(dir, host) == 0)
        host_ok();
    else
        host_fail("the longest encoded name is creatable",
                  "the symbol tier does not fit the budget");
}

int main(int argc, char **argv)
{
    char root[4096];

    section_golden();
    section_boundaries();
    section_shapes();
    section_utf8();
    section_i18n();

    if (host_scratch_root(argv[0], "elfuse-casefold", argc > 1 ? argv[1] : NULL,
                          root, sizeof(root)) < 0)
        return 1;

    section_alphabet(root);
    section_accept(root);
    section_volume(root);
    remove_tree(root);

    return host_summary("test-casefold-host");
}
