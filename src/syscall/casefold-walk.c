/*
 * Case-exact path resolution
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Applies the encoding in casefold.h to a whole path, asking the volume about
 * one component at a time. casefold-walk.h states the contract.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
/* fsobj_type_t and VLNK, for the ATTR_CMN_OBJTYPE the probe requests. */
#include <sys/vnode.h>
#include <unistd.h>

#include "utils.h"

#include "syscall/casefold-walk.h"
#include "syscall/path.h"
#include "syscall/proc.h"

bool casefold_active(void)
{
    return proc_get_sysroot() && proc_sysroot_casefold_enabled();
}

typedef enum {
    PROBE_ERROR = -1,
    PROBE_EXACT = 0,    /* an entry exists spelled exactly as asked */
    PROBE_FOLDED = 1,   /* an entry exists, but under a different spelling */
    PROBE_ABSENT = 2,   /* nothing is there */
    PROBE_UNUSABLE = 3, /* the volume refuses to hold this name at all */
    /* Nothing is there because a component of the prefix is not a directory.
     * Kept apart from PROBE_ABSENT because the two answer differently for a
     * caller deciding whether the sysroot has a claim on the path: resolution
     * stopped inside the tree (path_resolution(7)), so the path is the
     * sysroot's to answer for and owes ENOTDIR rather than falling through to
     * a host file that merely shares the literal spelling.
     */
    PROBE_NOTDIR = 4
} probe_result_t;

/* Scan the directory holding @path for an entry spelled exactly @leaf. Only
 * reached when the volume cannot report a stored spelling through
 * getattrlistat, which APFS and HFS+ both can; a network mount that folds case
 * might not. Costs a directory read, which is why it is the fallback and not
 * the primary.
 */
static probe_result_t probe_by_readdir(host_fd_t base_fd,
                                       const char *path,
                                       const char *leaf)
{
    char parent[LINUX_PATH_MAX];
    const char *slash = strrchr(path, '/');
    struct stat st;
    struct dirent *de;
    bool found = false;
    DIR *d;
    int fd;

    if (!slash) {
        /* A bare name is measured from @base_fd itself. */
        str_copy_trunc(parent, ".", sizeof(parent));
    } else {
        size_t n = slash == path ? 1 : (size_t) (slash - path);

        if (n >= sizeof(parent)) {
            errno = ENAMETOOLONG;
            return PROBE_ERROR;
        }
        memcpy(parent, path, n);
        parent[n] = '\0';
    }

    fd = openat(base_fd, parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return PROBE_ERROR;
    d = fdopendir(fd);
    if (!d) {
        close(fd);
        return PROBE_ERROR;
    }
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, leaf)) {
            found = true;
            break;
        }
    }
    closedir(d);
    if (found)
        return PROBE_EXACT;

    /* Missing from the listing is not the same as absent: the volume may hold
     * the name under a spelling that folded onto it, and a lookup by that name
     * will find it. Reporting absent here would send a create at the literal
     * name straight onto the other file.
     */
    if (fstatat(base_fd, path, &st, AT_SYMLINK_NOFOLLOW) == 0)
        return PROBE_FOLDED;
    if (errno == ENOTDIR)
        return PROBE_NOTDIR;
    return errno == ENOENT ? PROBE_ABSENT : PROBE_ERROR;
}

const char *casefold_attr_stored_name(const void *reply,
                                      size_t reply_cap,
                                      size_t ref_off)
{
    u_int32_t total;
    attrreference_t ref;

    if (reply_cap < sizeof(total))
        return NULL;
    /* memcpy, not a cast: the reply struct is packed and nothing guarantees
     * the caller's buffer aligns its fields.
     */
    memcpy(&total, reply, sizeof(total));

    size_t usable = total < reply_cap ? total : reply_cap;
    if (ref_off > usable || usable - ref_off < sizeof(ref))
        return NULL;
    memcpy(&ref, (const char *) reply + ref_off, sizeof(ref));

    /* attr_dataoffset is signed (int32_t); a negative one points before the
     * reference, outside anything the kernel wrote for this attribute.
     */
    if (ref.attr_dataoffset <= 0 || ref.attr_length == 0)
        return NULL;
    size_t name_off = ref_off + (size_t) ref.attr_dataoffset;
    if (name_off >= usable || ref.attr_length > usable - name_off)
        return NULL;

    const char *name = (const char *) reply + name_off;
    return memchr(name, '\0', ref.attr_length) ? name : NULL;
}

/* Does an entry spelled exactly @leaf sit at @path?
 *
 * A plain stat cannot answer this: the volume resolves names case- and
 * normalization-blind, so it reports success for a spelling that is not what is
 * stored, while Linux resolution is byte-exact and must report ENOENT for that.
 * getattrlistat goes through the same folding lookup but hands back the name as
 * stored, which is the byte comparison this needs. FSOPT_NOFOLLOW keeps the
 * question about the entry itself rather than a symlink's target, so a link is
 * judged by its own name.
 */
static probe_result_t probe_exact(host_fd_t base_fd,
                                  const char *path,
                                  const char *leaf,
                                  bool *is_link,
                                  bool *type_known)
{
    /* ATTR_CMN_OBJTYPE rides along on a request already being made, so knowing
     * whether the entry is a symlink costs nothing beyond the byte comparison
     * this call exists for. FSOPT_NOFOLLOW below already asks about the entry
     * rather than its target, so the answer is about the link itself.
     */
    struct attrlist al = {
        .bitmapcount = ATTR_BIT_MAP_COUNT,
        .commonattr =
            ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_OBJTYPE | ATTR_CMN_NAME,
    };
    /* Fixed-size attributes come back in ascending bit order, so ATTR_CMN_NAME
     * (0x1) precedes ATTR_CMN_OBJTYPE (0x8) and the variable-length name data
     * follows both. Ordering these fields any other way silently misreads every
     * field after the first. Only attributes the volume actually returned are
     * packed, so an absent one shifts every later field down by its width,
     * which is why obj_type is read under the ATTR_CMN_NAME test below rather
     * than beside it.
     */
    struct {
        u_int32_t length;
        attribute_set_t returned;
        attrreference_t name_ref;
        fsobj_type_t obj_type;
        char name[CASEFOLD_STORED_NAME_MAX];
    } __attribute__((aligned(4), packed)) attr_buf;

    *is_link = false;
    *type_known = false;

    if (getattrlistat(base_fd, path, &al, &attr_buf, sizeof(attr_buf),
                      FSOPT_NOFOLLOW) == 0) {
        const char *stored = NULL;
        if (attr_buf.returned.commonattr & ATTR_CMN_NAME)
            stored = casefold_attr_stored_name(
                &attr_buf, sizeof(attr_buf),
                (size_t) ((const char *) &attr_buf.name_ref -
                          (const char *) &attr_buf));
        if (stored) {
            /* Read here, not before the test: obj_type only sits at this
             * offset because name_ref precedes it, and it does so only when
             * the name was returned inside the reply's own bounds. With the
             * name withheld or the reply malformed the field would be read
             * past where the volume wrote it, and a garbage VLNK sends the
             * walk chasing a link that is not there.
             */
            size_t usable = attr_buf.length < sizeof(attr_buf)
                                ? attr_buf.length
                                : sizeof(attr_buf);
            size_t obj_end = (size_t) ((const char *) &attr_buf.obj_type -
                                       (const char *) &attr_buf) +
                             sizeof(attr_buf.obj_type);
            if ((attr_buf.returned.commonattr & ATTR_CMN_OBJTYPE) &&
                obj_end <= usable) {
                *is_link = attr_buf.obj_type == VLNK;
                *type_known = true;
            }
            if (!strcmp(stored, leaf))
                return PROBE_EXACT;
            /* A mismatch is not yet a fold. For a second hard link to a
             * symlink the volume reports the primary link's name here rather
             * than the one just looked up (observed on APFS; a second link to
             * a regular file reports itself), so an entry spelled exactly as
             * asked can still come back under another name. Only the listing
             * tells an aliased name from a genuinely folded one, and only a
             * mismatch pays for the scan.
             *
             * The listing carries no type, so whatever this call learned
             * describes the entry the volume named, not the one the listing
             * finds. Withdraw it rather than report for this name a type
             * that was never confirmed for it: all_types_known below is
             * what lets a caller skip a canonical containment recheck, so
             * an unconfirmed type there would vouch for a path no probe
             * ever typed.
             */
            *type_known = false;
            return probe_by_readdir(base_fd, path, leaf);
        }
        /* The call succeeded but the volume withheld the name or handed back
         * a reply whose bounds do not hold it, so there is no spelling to
         * compare. Say so rather than dispatching on an errno no one set,
         * which would pick a verdict out of whatever ran last.
         */
        errno = ENOTSUP;
    }

    switch (errno) {
    case ENOENT:
        return PROBE_ABSENT;
    case ENOTDIR:
        return PROBE_NOTDIR;
    case EILSEQ:
    case EINVAL:
        /* The volume will not hold this byte sequence as a name, so it can
         * never be there and can never be created there. Both answers are the
         * same: the name has to be escaped.
         *
         * EINVAL can also mean a malformed request rather than a malformed
         * name, and the two are indistinguishable here. It does not matter:
         * the attrlist is a compile-time constant, so a malformed one would
         * fail every probe in every directory rather than this one, which no
         * lookup in the suite would survive.
         */
        return PROBE_UNUSABLE;
    case ENOTSUP:
        return probe_by_readdir(base_fd, path, leaf);
    default:
        return PROBE_ERROR;
    }
}

/* Append "/@name" to @out, tracking the running length so the walk does not
 * rescan what it has already built.
 */
static int append_component(char *out,
                            size_t outsz,
                            size_t *len,
                            const char *name)
{
    size_t name_len = strlen(name);
    size_t pos = *len;

    /* No separator before the first component: an empty prefix means the walk
     * is measured from a descriptor, and a leading '/' would make the result
     * absolute and resolve it against the host root instead.
     */
    if (pos != 0 && out[pos - 1] != '/') {
        if (pos + 1 >= outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        out[pos++] = '/';
    }
    if (pos + name_len >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out + pos, name, name_len + 1);
    *len = pos + name_len;
    return 0;
}

/* Append a component and record where it landed. Predicting the offset instead
 * gets it wrong whenever append_component omits the separator: an empty prefix,
 * or a prefix that already ends in one, as a root sysroot does.
 */
static int append_leaf(char *out,
                       size_t outsz,
                       size_t *len,
                       const char *name,
                       casefold_walk_t *walk)
{
    size_t name_len = strlen(name);

    walk->parent_offset = *len;
    if (append_component(out, outsz, len, name) < 0)
        return -1;
    walk->leaf_offset = *len - name_len;
    return 0;
}

/* The on-disk name a guest component takes when nothing can be probed for it,
 * either because it is absent or because its parent is. Escaping depends only
 * on the name, so this needs no filesystem access.
 */
static int name_by_rule(const char *guest, char *out, size_t outsz)
{
    if (!casefold_needs_escape(guest)) {
        if (strlen(guest) + 1 > outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(out, guest, strlen(guest) + 1);
        return 0;
    }
    return casefold_escape(guest, out, outsz);
}

/* Probe @cand against the parent already spelled in @out[0..len), appending it
 * in place so the accumulated prefix is never recopied per component. @out is
 * restored to that prefix on every exit, including the append's own
 * ENAMETOOLONG: the separator is written before the length check that rejects
 * an over-long candidate, so an unrestored buffer would keep a trailing '/'.
 */
static probe_result_t probe_candidate(host_fd_t base_fd,
                                      char *out,
                                      size_t outsz,
                                      size_t len,
                                      const char *cand,
                                      bool *is_link,
                                      bool *type_known)
{
    size_t probe_len = len;
    probe_result_t verdict;

    if (append_component(out, outsz, &probe_len, cand) < 0) {
        out[len] = '\0';
        return PROBE_ERROR;
    }
    verdict = probe_exact(base_fd, out, cand, is_link, type_known);
    out[len] = '\0';
    return verdict;
}

/* Spell one component, given the parent already spelled in @out. The entry is
 * there exactly when the verdict is PROBE_EXACT; the host spelling goes to
 * @host either way. @out doubles as the probe buffer: each candidate is
 * appended in place and the terminator restored before returning, so the
 * accumulated prefix is never recopied per component. A candidate that does
 * not fit reports ENAMETOOLONG exactly as the final spelling would, since an
 * escape is never shorter than the literal it stands for.
 */
static probe_result_t resolve_component(host_fd_t base_fd,
                                        char *out,
                                        size_t outsz,
                                        size_t len,
                                        const char *guest,
                                        char *host,
                                        size_t hostsz,
                                        bool *is_link,
                                        bool *type_known)
{
    probe_result_t verdict;

    /* An escape-shaped guest name is stored escaped unconditionally, so it can
     * never be mistaken for the encoding of a different name. Probing its
     * literal spelling would find some unrelated file.
     */
    if (!casefold_is_escaped(guest)) {
        verdict = probe_candidate(base_fd, out, outsz, len, guest, is_link,
                                  type_known);
        if (verdict == PROBE_ERROR)
            return PROBE_ERROR;
        if (verdict == PROBE_EXACT) {
            if (str_copy_trunc(host, guest, hostsz) >= hostsz) {
                errno = ENAMETOOLONG;
                return PROBE_ERROR;
            }
            return PROBE_EXACT;
        }
    } else {
        /* An escape-shaped guest name can only live at its own escape, so the
         * literal slot says nothing about it and is left unprobed: whatever
         * sits there encodes a different name. Absent until the escape probe
         * below says otherwise.
         */
        verdict = PROBE_ABSENT;
        *type_known = false;
    }

    /* The literal spelling is not what is stored. Whatever the reason (a
     * differently-spelled sibling in the slot, a name the volume refuses, or
     * simply nothing there), the escape is the only other place the name can
     * live, so ask whether it does.
     *
     * The escape cannot fail here: path_component_copy delivered a non-empty,
     * slash-free name of at most CASEFOLD_GUEST_NAME_MAX bytes, "." and ".."
     * never reach a probe, and @host is sized by CASEFOLD_HOST_NAME_MAX,
     * which casefold.h statically proves large enough for any legal guest
     * name. A failure means a broken precondition, so fail closed rather than
     * guess a spelling.
     */
    if (casefold_escape(guest, host, hostsz) < 0)
        return PROBE_ERROR;

    probe_result_t escape_verdict =
        probe_candidate(base_fd, out, outsz, len, host, is_link, type_known);
    switch (escape_verdict) {
    case PROBE_EXACT:
        return PROBE_EXACT;
    case PROBE_ERROR:
        return PROBE_ERROR;
    default:
        break;
    }

    /* Neither spelling is there. Which one the name would take is decided by
     * the name alone, which is what keeps two processes creating colliding
     * names off the same slot.
     */
    if (verdict == PROBE_ABSENT || verdict == PROBE_NOTDIR)
        return name_by_rule(guest, host, hostsz) < 0 ? PROBE_ERROR : verdict;
    /* The slot is taken by a different spelling, or refused outright, so the
     * name belongs at its escape even though nothing is there yet. Reported as
     * folded rather than absent: the two differ to a caller deciding whether
     * the sysroot has a claim on this path.
     *
     * A refused name converges on the same answer as an occupied slot, which
     * is why PROBE_UNUSABLE needs no separate verdict of its own. Both mean the
     * sysroot owns this path and the caller must not look for it on the host.
     * The difference is why the literal spelling is unavailable, and no caller
     * asks that. Deliberately fail-closed: the alternative sends a guest asking
     * for an ill-formed name out to whatever the host happens to hold.
     */
    return PROBE_FOLDED;
}

casefold_verdict_t casefold_resolve_at(host_fd_t base_fd,
                                       const char *base_host_prefix,
                                       const char *guest_path,
                                       bool follow_final,
                                       char *out,
                                       size_t outsz,
                                       casefold_walk_t *walk)
{
    const char *scan = guest_path;
    const char *comp;
    size_t comp_len;
    size_t len;
    bool absent = false;
    casefold_walk_t local;

    if (!walk)
        walk = &local;
    walk->parent_found = true;
    walk->parent_offset = 0;
    walk->link_rest_offset = 0;
    walk->link_guest_offset = 0;
    walk->leaf_offset = 0;
    walk->folded = false;
    walk->notdir = false;
    walk->leaf_type_known = false;
    walk->leaf_is_link = false;
    walk->all_types_known = true;

    len = str_copy_trunc(out, base_host_prefix ? base_host_prefix : "", outsz);
    if (len >= outsz) {
        errno = ENAMETOOLONG;
        return CASEFOLD_ERROR;
    }

    while (path_next_component(&scan, &comp, &comp_len)) {
        char guest[CASEFOLD_GUEST_NAME_MAX + 1];
        char host[CASEFOLD_HOST_NAME_MAX + 1];

        if (path_component_copy(guest, sizeof(guest), comp, comp_len) < 0)
            return CASEFOLD_ERROR;

        /* "." and ".." navigate rather than name an entry, so they are spelled
         * through untouched. An absolute path arrives collapsed by
         * construction: the resolvers normalize at entry and after every
         * spliced link target. A dirfd-relative one may still carry them, and
         * the host kernel resolves those against the real descriptor.
         */
        if (!strcmp(guest, ".") || !strcmp(guest, "..")) {
            walk->leaf_type_known = false;
            walk->leaf_is_link = false;
            if (append_leaf(out, outsz, &len, guest, walk) < 0)
                return CASEFOLD_ERROR;
            continue;
        }

        if (absent) {
            /* Below a component that is not there, nothing can be probed, and
             * nothing needs to be: the spelling follows from the name.
             */
            walk->parent_found = false;
            walk->leaf_type_known = false;
            walk->leaf_is_link = false;
            if (name_by_rule(guest, host, sizeof(host)) < 0)
                return CASEFOLD_ERROR;
        } else {
            bool is_link = false;
            bool type_known = false;
            probe_result_t verdict =
                resolve_component(base_fd, out, outsz, len, guest, host,
                                  sizeof(host), &is_link, &type_known);

            if (verdict == PROBE_ERROR)
                return CASEFOLD_ERROR;
            walk->leaf_type_known = verdict == PROBE_EXACT && type_known;
            walk->leaf_is_link = walk->leaf_type_known && is_link;
            if (verdict == PROBE_EXACT && !type_known)
                walk->all_types_known = false;

            /* A link the walk has to pass through stops it. That is every
             * intermediate component, and the final one only when the caller
             * asked to follow: path_resolution(7) applies nofollow to the last
             * component alone.
             *
             * The host cannot be asked to follow it instead. A link records the
             * bytes the guest wrote, and those name a guest path: a component
             * of it may be stored escaped, and an absolute one starts at the
             * sysroot rather than at the host root. Handing them to the kernel
             * looks somewhere else entirely.
             */
            if (verdict == PROBE_EXACT && is_link) {
                const char *rest = scan;

                while (*rest == '/')
                    rest++;
                if (*rest != '\0' || follow_final) {
                    if (append_leaf(out, outsz, &len, host, walk) < 0)
                        return CASEFOLD_ERROR;
                    walk->link_guest_offset = (size_t) (comp - guest_path);
                    walk->link_rest_offset = (size_t) (rest - guest_path);
                    return CASEFOLD_SYMLINK;
                }
            }
            /* A fold means the sysroot holds an entry where the guest asked,
             * under a spelling the guest did not use. Recorded for the caller
             * because it is the one absent verdict that must not fall through
             * to the host: something is already there.
             */
            if (verdict == PROBE_FOLDED)
                walk->folded = true;
            /* Resolution stopped at a component that is not a directory, so
             * the sysroot has answered and the caller must not look for the
             * path on the host. Recorded rather than returned immediately so
             * out still receives the remaining components: a caller reporting
             * the error issues its own syscall against the whole spelling.
             */
            if (verdict == PROBE_NOTDIR)
                walk->notdir = true;
            absent = verdict != PROBE_EXACT;
        }

        if (append_leaf(out, outsz, &len, host, walk) < 0)
            return CASEFOLD_ERROR;
    }

    if (absent)
        return CASEFOLD_ABSENT;

    /* The probe deliberately stops at a symlink rather than following it, so a
     * caller that asked about the target has to say so. A link pointing
     * nowhere is absent for that caller, which is what an access(2) probe
     * would report. When the leaf's own probe answered its type it is a known
     * non-link (a known link already returned CASEFOLD_SYMLINK above), so
     * following adds nothing and the extra host probe is skipped; the readdir
     * fallback and a dot leaf leave the type unknown and keep it.
     */
    if (follow_final && !walk->leaf_type_known &&
        faccessat(base_fd, out, F_OK, 0) < 0)
        return CASEFOLD_ABSENT;
    return CASEFOLD_FOUND;
}
