/*
 * Shared utilities for the native host test binaries
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The filename tests that run as native macOS binaries (rather than as guest
 * programs under elfuse) need to build UTF-8 by hand, ask the volume what
 * spelling it actually stored, and clear a scratch tree afterwards. This is the
 * host-side counterpart of test-util.h, which serves the guest tests and is
 * built for a different target.
 */

#pragma once

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <unistd.h>

/* Encode one code point as UTF-8 into @o, which needs four bytes of room.
 * Returns the number written. Hand-rolled because the tests build names from
 * code points chosen for their folding behavior, and iconv would drag a locale
 * into an assertion about bytes.
 */
static inline int utf8_put(char *o, unsigned cp)
{
    if (cp < 0x80) {
        o[0] = (char) cp;
        return 1;
    }
    if (cp < 0x800) {
        o[0] = (char) (0xC0 | cp >> 6);
        o[1] = (char) (0x80 | (cp & 63));
        return 2;
    }
    if (cp < 0x10000) {
        o[0] = (char) (0xE0 | cp >> 12);
        o[1] = (char) (0x80 | ((cp >> 6) & 63));
        o[2] = (char) (0x80 | (cp & 63));
        return 3;
    }
    o[0] = (char) (0xF0 | cp >> 18);
    o[1] = (char) (0x80 | ((cp >> 12) & 63));
    o[2] = (char) (0x80 | ((cp >> 6) & 63));
    o[3] = (char) (0x80 | (cp & 63));
    return 4;
}

/* The spelling @dir/@name is stored under, or NULL if the volume will not say.
 *
 * This is the primitive the whole scheme rests on: stat(2) reports success for
 * a spelling that is not what is stored, so only asking for the name back can
 * tell "exists as spelled" from "exists under a spelling that folded onto it".
 * FSOPT_NOFOLLOW because a symlink's own name is the question, not its
 * target's. Returns a pointer to static storage, valid until the next call.
 *
 * The reply is bounds-checked before the reference and the name are read:
 * attr_dataoffset and attr_length come from the filesystem, and --sysroot may
 * name an SMB or NFS mount that need not fill them the way APFS does. This
 * mirrors casefold_attr_stored_name rather than calling it: of the three
 * lanes including this header, only test-casefold-walk-host links
 * casefold-walk.o.
 */
static inline const char *disk_name(const char *dir, const char *name)
{
    static char out[1024];
    char path[8192];
    struct attrlist al = {
        .bitmapcount = ATTR_BIT_MAP_COUNT,
        .commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME,
    };
    struct {
        u_int32_t length;
        attribute_set_t returned;
        attrreference_t name_ref;
        char name[1024];
    } __attribute__((aligned(4), packed)) buf = {0};

    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int) sizeof(path))
        return NULL;
    if (getattrlistat(AT_FDCWD, path, &al, &buf, sizeof(buf), FSOPT_NOFOLLOW) <
        0)
        return NULL;
    if (!(buf.returned.commonattr & ATTR_CMN_NAME))
        return NULL;

    /* The reference itself is checked against the reply before its fields are
     * read: a volume can set ATTR_CMN_NAME in returned yet write a reply too
     * short to hold the reference, and buf past buf.length is only zeros.
     */
    size_t usable = buf.length < sizeof(buf) ? buf.length : sizeof(buf);
    size_t ref_off =
        (size_t) ((const char *) &buf.name_ref - (const char *) &buf);
    if (ref_off > usable || usable - ref_off < sizeof(buf.name_ref))
        return NULL;

    /* attr_dataoffset is signed; a negative one points before the reference,
     * outside anything the kernel wrote for this attribute.
     */
    if (buf.name_ref.attr_dataoffset <= 0 || buf.name_ref.attr_length == 0)
        return NULL;
    size_t name_off = ref_off + (size_t) buf.name_ref.attr_dataoffset;
    if (name_off >= usable || buf.name_ref.attr_length > usable - name_off)
        return NULL;

    const char *stored = (const char *) &buf + name_off;
    /* No NUL inside the declared length means the name is not a C string, and
     * "%s" would read past what the volume wrote.
     */
    if (!memchr(stored, '\0', buf.name_ref.attr_length))
        return NULL;
    snprintf(out, sizeof(out), "%s", stored);
    return out;
}

static inline int remove_entry(const char *path,
                               const struct stat *st,
                               int flag,
                               struct FTW *ftw)
{
    (void) st;
    (void) flag;
    (void) ftw;
    return remove(path);
}

/* Clear a scratch tree. nftw(3) rather than system("rm -rf"), which
 * .ci/check-security.sh rejects and which would build a shell command from a
 * path the test composed.
 */
static inline void remove_tree(const char *path)
{
    /* Depth-first and physical, so the walk removes children before their
     * parent and never follows a symlink fixture out of the scratch tree.
     */
    if (nftw(path, remove_entry, 16, FTW_DEPTH | FTW_PHYS) < 0)
        fprintf(stderr, "warning: could not remove %s: %s\n", path,
                strerror(errno));
}
