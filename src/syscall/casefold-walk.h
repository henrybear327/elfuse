/*
 * Case-exact path resolution
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Resolves a guest path to its host spelling one component at a time, applying
 * the escape from casefold.h where a name cannot be stored as itself. Kept
 * apart from the codec so the codec stays a leaf translation unit that a host
 * unit test can link on its own. See docs/filenames.md.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "syscall/casefold.h"
#include "syscall/internal.h"

/* True when guest names have to be reconciled with the volume at all: a sysroot
 * is configured and it lives somewhere that folds case. On a byte-exact volume
 * every name is stored as itself and nothing here does any work.
 */
bool casefold_active(void);

/* Longest name the volume can hand back, in bytes: 255 UTF-16 code units at up
 * to three UTF-8 bytes each. Larger than CASEFOLD_HOST_NAME_MAX, which bounds
 * only the escapes elfuse writes. A literal name the host already holds, such
 * as a full-length CJK one, is longer than any escape. Any buffer receiving a
 * stored spelling has to be sized by this.
 */
#define CASEFOLD_STORED_NAME_MAX (CASEFOLD_UNIT_MAX * 3 + 1)

typedef enum {
    CASEFOLD_ERROR = -1, /* the probe failed; errno is set */
    CASEFOLD_FOUND = 0,  /* every component resolved; out names the object */
    CASEFOLD_ABSENT = 1, /* out is where the object would have to live */
    /* A component the walk had to pass through is a symlink. out names that
     * link in host spelling; the caller resolves the target in the guest
     * namespace and comes back with the spliced path. The walk does not follow
     * it itself, because where an absolute target lands is a dispatch question
     * (sysroot or host), and the walk sees only the sysroot side.
     */
    CASEFOLD_SYMLINK = 2,
} casefold_verdict_t;

typedef struct {
    /* Every component but the last resolved. Answers the create resolver's
     * question "can this be created here", which a plain access(2) on a
     * naively concatenated parent gets wrong, because that folds case.
     */
    bool parent_found;
    /* Offset in out of the final component, so a caller can split parent from
     * leaf without a strrchr that could walk back into the host prefix.
     */
    size_t leaf_offset;
    /* Length of out before the final component was appended: truncating there
     * yields the parent's spelling exactly. Recorded by the walk because only
     * it knows whether a separator was inserted before the leaf. A prefix that
     * already ends in one, as a root sysroot does, gets none, so a caller
     * subtracting one from leaf_offset instead reconstructs an empty parent
     * where the parent is the root.
     */
    size_t parent_offset;
    /* Some component's slot is held by an entry spelled differently, or by one
     * the volume refuses to store. The path is absent to a byte-exact reader
     * but the sysroot does hold something there, so a caller must report ENOENT
     * rather than treat the path as unclaimed and look for it on the host.
     */
    bool folded;
    /* Some component of the path is not a directory, so resolution stopped
     * there (path_resolution(7)) and everything below it owes ENOTDIR. Absent
     * for the same reason folded is: the path is not there, but the sysroot
     * decided that, so a caller must report the error rather than treat the
     * path as unclaimed and look for it on the host.
     */
    bool notdir;
    /* Set with CASEFOLD_SYMLINK: the byte offset in the guest path at which
     * the components after the link begin, or the path length when the link
     * was the final component.
     */
    size_t link_rest_offset;
    /* Offset in the guest path of the link component itself, so the caller can
     * rebuild the directory a relative target is measured from.
     */
    size_t link_guest_offset;
    /* Object type of the last component a probe answered, for a FOUND path
     * its leaf. leaf_type_known is false when the readdir fallback answered,
     * since a listing carries no type, and for dot components, which are
     * never probed. Spares a caller one fstatat per component where the
     * probe already paid for ATTR_CMN_OBJTYPE.
     */
    bool leaf_type_known;
    bool leaf_is_link;
} casefold_walk_t;

/* Resolve @guest_path, interpreted relative to @base_fd, into its host spelling
 * in @out. @out is seeded with @base_host_prefix (the sysroot for an absolute
 * guest path, the empty string for a dirfd-relative one) and grown a component
 * at a time. Nothing is opened: each probe is a getattrlistat against
 * the prefix accumulated so far, so the walk holds no descriptors and has no
 * cleanup path.
 *
 * Per component, once the parent is spelled in @out:
 *
 *   exists, spelled as asked    -> the literal name
 *   exists, spelled differently -> the escape, whose slot is therefore free
 *   the volume refuses the name -> the escape
 *   absent                      -> the escape if that exists, otherwise the
 *                                  literal name for a fold-stable name and the
 *                                  escape for any other
 *
 * A folded component yields its escape even though nothing is there. That name
 * provably does not exist and cannot fold onto the sibling occupying the slot,
 * so a caller running its syscall against @out gets the ENOENT Linux would give
 * for a wrong-case lookup, with no separate veto path.
 *
 * Once a component is absent the rest cannot be probed, and do not need to be:
 * escaping depends only on the name, so the remainder is spelled directly.
 *
 * @follow_final rechecks the resolved object through symlinks, so a dangling
 * link reports absent, matching what an access(2) existence probe would say.
 *
 * @walk may be NULL when the caller needs only the verdict and @out.
 *
 * @out doubles as the walk's probe scratch, so it must not overlap
 * @guest_path or @base_host_prefix, and it holds nothing meaningful once
 * CASEFOLD_ERROR is returned.
 */
casefold_verdict_t casefold_resolve_at(host_fd_t base_fd,
                                       const char *base_host_prefix,
                                       const char *guest_path,
                                       bool follow_final,
                                       char *out,
                                       size_t outsz,
                                       casefold_walk_t *walk);

/* Validate and locate the variable-length ATTR_CMN_NAME payload in a
 * getattrlist reply. getattrlist(2) documents that a truncated reply can carry
 * an attrreference whose data starts or ends past the buffer, so nothing in
 * the reply may be dereferenced on the kernel's word alone; APFS stays inside
 * the documented bound, but --sysroot accepts network mounts that need not.
 *
 * @reply is the buffer handed to getattrlistat, whose first u_int32_t is the
 * length the kernel claims; @reply_cap is that buffer's size; @ref_off is the
 * byte offset of the name's attrreference_t within it. Returns the
 * NUL-terminated stored name, or NULL when any bound fails or no NUL exists
 * inside the referenced bytes. Non-static only for the host unit test, which
 * cannot forge a malformed reply through a real volume.
 */
const char *casefold_attr_stored_name(const void *reply,
                                      size_t reply_cap,
                                      size_t ref_off);
