/*
 * Report how a volume treats filenames
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Every table in docs/filenames.md is a measurement of what the filesystem
 * underneath actually does, and this program is what produces them. It is
 * informational, not an assertion: it reports everything, including behavior
 * elfuse is deliberately immune to, because that is what someone investigating
 * a surprise wants to see. The assertions live in tests/test-casefold-host.c,
 * which pins only the facts the design depends on.
 *
 *     make probe-volume-naming                     # a temp dir
 *     build/probe-volume-naming /Volumes/cs-image  # any other volume
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

#include "host-test-util.h"

static const char *root;

static int mk(const char *dir, const char *name)
{
    char p[9000];
    int fd;

    if (snprintf(p, sizeof(p), "%s/%s", dir, name) >= (int) sizeof(p))
        return -ENAMETOOLONG;
    fd = open(p, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0)
        return -errno;
    close(fd);
    return 0;
}

static const char *verdict(const char *dir, const char *name)
{
    const char *d = disk_name(dir, name);
    const char *leaf = strrchr(name, '/');

    if (!d)
        return errno == ENOENT || errno == ENOTDIR ? "ABSENT" : "ERROR";
    /* The probe reports the leaf's stored spelling, so compare against the
     * leaf of what was asked for and not against the whole relative path.
     */
    return !strcmp(d, leaf ? leaf + 1 : name) ? "EXACT" : "FOLDED";
}

/* ------------------------------------------------------- 1. byte-exactness */

static void section_exactness(void)
{
    char dir[4096], p[8192], real[PATH_MAX];
    int fd;

    puts("1. case preservation and byte-exactness");
    snprintf(dir, sizeof(dir), "%s/exact", root);
    mkdir(dir, 0755);
    snprintf(p, sizeof(p), "%s/Alpha", dir);
    mkdir(p, 0755);
    snprintf(p, sizeof(p), "%s/Alpha/Beta.txt", dir);
    fd = open(p, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0)
        close(fd);

    snprintf(p, sizeof(p), "%s/alpha/beta.TXT", dir);
    if (realpath(p, real)) {
        const char *b = strstr(real, "/exact/");
        printf("   realpath of a wrong-case spelling  %s\n", b ? b : real);
    } else {
        printf("   realpath of a wrong-case spelling  %s\n", strerror(errno));
    }
    fd = open(p, O_RDONLY);
    if (fd >= 0) {
        char gp[PATH_MAX];
        if (fcntl(fd, F_GETPATH, gp) == 0) {
            const char *b = strstr(gp, "/exact/");
            printf("   F_GETPATH of the same open        %s\n", b ? b : gp);
        }
        close(fd);
    } else {
        printf("   open of a wrong-case spelling     %s\n", strerror(errno));
    }

    snprintf(p, sizeof(p), "%s/Alpha/beta.txt", dir);
    fd = open(p, O_CREAT | O_EXCL | O_WRONLY, 0644);
    printf("   sibling differing only by case    %s\n",
           fd >= 0 ? "created (volume is case-sensitive)" : strerror(errno));
    if (fd >= 0)
        close(fd);

    int bad = mk(dir,
                 "bad\xff\xfe"
                 "name");
    printf("   name that is not valid UTF-8      %s\n",
           bad == 0 ? "created" : strerror(-bad));
    putchar('\n');
}

/* ------------------------------------------------------- 2. probe verdicts */

static void section_verdicts(void)
{
    char dir[4096], p[8192];
    int fd;

    puts("2. byte-exact probe verdicts (what the resolver sees)");
    snprintf(dir, sizeof(dir), "%s/walk", root);
    mkdir(dir, 0755);
    snprintf(p, sizeof(p), "%s/usr", dir);
    mkdir(p, 0755);
    snprintf(p, sizeof(p), "%s/usr/lib", dir);
    mkdir(p, 0755);
    snprintf(p, sizeof(p), "%s/usr/lib/Libc.So", dir);
    fd = open(p, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0)
        close(fd);
    snprintf(p, sizeof(p), "%s/lib", dir);
    if (symlink("usr/lib", p) < 0 && errno != EEXIST)
        printf("   (symlink fixture failed: %s)\n", strerror(errno));

    printf("   %-34s %s\n", "lib (a symlink)", verdict(dir, "lib"));
    printf("   %-34s %s\n", "lib/Libc.So  through the symlink",
           verdict(dir, "lib/Libc.So"));
    printf("   %-34s %s\n", "lib/libc.so  wrong-case leaf",
           verdict(dir, "lib/libc.so"));
    printf("   %-34s %s  <- a full-path probe validates\n",
           "LIB/Libc.So  wrong-case parent", verdict(dir, "LIB/Libc.So"));
    printf("   %-34s %s     only the LAST component, which is why\n", "", "");
    printf("   %-34s %s     resolution probes every prefix\n", "", "");
    printf("   %-34s %s\n", "lib/Nope     absent", verdict(dir, "lib/Nope"));
    putchar('\n');
}

/* --------------------------------------------------------- 3. folding table */

static void pair(const char *dir,
                 const char *label,
                 const char *a,
                 const char *b)
{
    int ra = mk(dir, a);
    int rb = mk(dir, b);
    const char *da = disk_name(dir, a);

    printf("   %-34s %-9s stored as %s\n", label,
           rb == -EEXIST ? "COLLIDE" : (rb == 0 ? "distinct" : strerror(-rb)),
           da ? da : (ra == 0 ? "?" : strerror(-ra)));
}

static void section_folding(void)
{
    char dir[4096];

    puts("3. what the folding table does");
    snprintf(dir, sizeof(dir), "%s/fold", root);
    mkdir(dir, 0755);

    pair(dir, "ascii Foo / foo", "Foo", "foo");
    pair(dir, "french cafe NFC / NFD", "caf\xc3\xa9", "cafe\xcc\x81");
    pair(dir, "french Ete / ete", "\xc3\x89t\xc3\xa9", "\xc3\xa9t\xc3\xa9");
    pair(dir, "german uber NFC / NFD",
         "\xc3\xbc"
         "ber",
         "u\xcc\x88"
         "ber");
    pair(dir, "german strasse / sharp-s", "strasse",
         "stra\xc3\x9f"
         "e");
    pair(dir, "german MASS / Mass", "MASS", "Mass");
    pair(dir, "turkish dotless i / ascii i",
         "\xc4\xb1"
         "d",
         "id");
    pair(dir, "turkish I-dot / ascii i",
         "\xc4\xb0"
         "z",
         "iz");
    pair(dir, "greek final / medial sigma", "\xcf\x83o\xcf\x82",
         "\xcf\x83o\xcf\x83");
    pair(dir, "greek SIGMA / sigma", "\xce\xa3q\xcf\x82", "\xcf\x83q\xcf\x82");
    pair(dir, "cyrillic DA / da", "\xd0\x94\xd0\x90", "\xd0\xb4\xd0\xb0");
    pair(dir, "chinese doc / file", "\xe6\x96\x87\xe6\xa1\xa3.txt",
         "\xe6\x96\x87\xe4\xbb\xb6.txt");
    pair(dir, "japanese ga NFC / NFD", "\xe3\x81\x8c",
         "\xe3\x81\x8b\xe3\x82\x99");
    pair(dir, "korean han NFC / jamo", "\xed\x95\x9c",
         "\xe1\x84\x92\xe1\x85\xa1\xe1\x86\xab");
    pair(dir, "ohm U+2126 / omega U+03A9",
         "\xe2\x84\xa6"
         "a",
         "\xce\xa9"
         "a");
    pair(dir, "angstrom U+212B / A-ring",
         "\xe2\x84\xab"
         "c",
         "\xc3\x85"
         "c");
    pair(dir, "ligature fi U+FB01 / 'fi'",
         "\xef\xac\x81"
         "b",
         "fib");
    pair(dir, "vietnamese NFC / NFD",
         "\xe1\xbb\x87"
         "d",
         "e\xcc\xa3\xcc\x82"
         "d");
    pair(dir, "devanagari NFC / NFD",
         "\xe0\xa4\xa9"
         "e",
         "\xe0\xa4\xa8\xe0\xa4\xbc"
         "e");
    pair(dir, "hebrew U+FB2E / NFD",
         "\xef\xac\xae"
         "f",
         "\xd7\x90\xd6\xb7"
         "f");
    pair(dir, "deseret U+10400 / U+10428",
         "\xf0\x90\x90\x80"
         "y",
         "\xf0\x90\x90\xa8"
         "y");
    pair(dir, "cherokee U+13A0 / U+13F8",
         "\xe1\x8e\xa0"
         "x",
         "\xe1\x8f\xb8"
         "x");
    pair(dir, "emoji rocket / star", "\xf0\x9f\x9a\x80", "\xe2\xad\x90");
    pair(dir, "CJK unified U+4E00 / U+4E01",
         "\xe4\xb8\x80"
         "p",
         "\xe4\xb8\x81"
         "p");
    pair(dir, "CJK compat U+F900 / U+8C48",
         "\xef\xa4\x80"
         "g",
         "\xe8\xb1\x88"
         "g");
    putchar('\n');
}

/* ---------------------------------------------------- 4. name length limits */

static void sweep(const char *dir,
                  const char *label,
                  unsigned cp,
                  int units_per,
                  int bytes_per)
{
    int lo = 0;

    for (int n = 1; n <= 300; n++) {
        char name[4096];
        int len = 0;
        for (int i = 0; i < n; i++)
            len += utf8_put(name + len, cp);
        name[len] = '\0';
        if (mk(dir, name) == 0)
            lo = n;
        else
            break;
    }
    printf("   %-22s max %3d chars = %4d bytes = %3d utf16 units\n", label, lo,
           lo * bytes_per, lo * units_per);
}

static void section_name_length(void)
{
    char dir[4096];

    puts(
        "4. component length limit (pathconf says NAME_MAX, but in what "
        "unit?)");
    snprintf(dir, sizeof(dir), "%s/namelen", root);
    mkdir(dir, 0755);
    printf("   pathconf(_PC_NAME_MAX) = %ld, NAME_MAX macro = %d\n",
           pathconf(dir, _PC_NAME_MAX), NAME_MAX);
    sweep(dir, "ascii U+0061", 0x61, 1, 1);
    sweep(dir, "latin-1 U+00E9", 0xE9, 1, 2);
    sweep(dir, "BMP/CJK U+6587", 0x6587, 1, 3);
    sweep(dir, "non-BMP U+1F680", 0x1F680, 2, 4);
    puts("   -> the limit is constant in UTF-16 units, not in bytes");
    putchar('\n');
}

/* ---------------------------------------------------- 5. path length limit */

static void section_path_length(void)
{
    char dir[4096], p[16384];
    char comp[101];
    int n;

    puts("5. whole-path limit");
    snprintf(dir, sizeof(dir), "%s/pathlen", root);
    mkdir(dir, 0755);
    printf("   macOS PATH_MAX = %d, pathconf(_PC_PATH_MAX) = %ld\n", PATH_MAX,
           pathconf(dir, _PC_PATH_MAX));
    puts("   Linux PATH_MAX = 4096 (what a guest may build)");

    memset(comp, 'd', 100);
    comp[100] = '\0';
    n = snprintf(p, sizeof(p), "%s", dir);
    for (int i = 0; i < 60; i++) {
        int add = snprintf(p + n, sizeof(p) - n, "/%s", comp);
        if (mkdir(p, 0755) < 0) {
            printf("   mkdir fails at depth %d, path length %d: %s\n", i + 1,
                   n + add, strerror(errno));
            break;
        }
        n += add;
    }
    putchar('\n');
}

/* -------------------------------------------------------- 6. payload alphabet
 */

static void section_alphabet(void)
{
    char dir[4096], name[8192];
    int collisions = 0, made = 0, len = 0;

    puts("6. payload alphabet U+4E00..U+5DFF (4096 symbols)");
    snprintf(dir, sizeof(dir), "%s/alpha", root);
    mkdir(dir, 0755);
    for (unsigned v = 0; v < 4096; v++) {
        char one[8];
        int l = utf8_put(one, 0x4E00 + v);
        one[l] = '\0';
        int rc = mk(dir, one);
        if (rc == 0)
            made++;
        else if (rc == -EEXIST)
            collisions++;
    }
    printf("   %d of 4096 distinct, %d collided\n", made, collisions);

    len = snprintf(name, sizeof(name), ".ef=");
    for (int i = 0; i < 171; i++)
        len += utf8_put(name + len, 0x4E00 + (unsigned) (i * 24 % 4096));
    name[len] = '\0';
    printf("   worst-case escaped name (%d bytes, %d units): %s\n", len,
           4 + 171, mk(dir, name) == 0 ? "created" : strerror(errno));
    putchar('\n');
}

int main(int argc, char **argv)
{
    char tmpl[4096];

    if (host_scratch_root(argv[0], "elfuse-probe", argc > 1 ? argv[1] : NULL,
                          tmpl, sizeof(tmpl)) < 0)
        return 1;
    root = tmpl;
    printf("probing %s\n\n", root);

    section_exactness();
    section_verdicts();
    section_folding();
    section_name_length();
    section_path_length();
    section_alphabet();

    remove_tree(root);
    return 0;
}
