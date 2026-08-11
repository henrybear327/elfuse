/*
 * Case-folding filename representation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A Linux guest names files by exact bytes; the default APFS volume matches
 * names case- and normalization-blind, so "Foo" and "foo" cannot coexist there.
 * A name that cannot be stored under its own spelling is stored escaped, and
 * the escape is a pure function of the name: no side table is needed to reverse
 * it, which is what keeps the whole mechanism lock-free and stateless.
 *
 * This header is the codec alone: no syscalls, no project dependencies, so it
 * links into a host-side unit test on its own. Resolving a path through the
 * escape lives in casefold-walk.c. See docs/filenames.md for the model.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

/* Marks an escaped name. Four ASCII bytes, charged against the same per-name
 * budget as the payload, so it stays short. The leading '.' keeps escaped names
 * out of a casual host-side listing. The separator is '=' and not '^' because
 * host-side tooling matches this prefix constantly and '^' is an anchor in both
 * basic and extended regular expressions, so grep -E '.ef\^' matches nothing
 * while reading as though it should.
 */
#define CASEFOLD_PREFIX ".ef="
#define CASEFOLD_PREFIX_LEN (sizeof(CASEFOLD_PREFIX) - 1)

/* Linux caps a path component at 255 bytes and bakes that into d_name[256], so
 * no guest can hand over or receive a longer name.
 */
#define CASEFOLD_GUEST_NAME_MAX 255

/* APFS caps a component at 255 UTF-16 code units, not bytes. An ASCII payload
 * therefore spends one unit per character while a BMP payload spends one unit
 * per character but carries 12 bits, which is what lets the long tier hold a
 * full-length guest name. See docs/filenames.md.
 */
#define CASEFOLD_UNIT_MAX 255

/* Longest guest name the hex tier can hold: CASEFOLD_PREFIX_LEN + 2n <= 255. */
#define CASEFOLD_HEX_MAX ((CASEFOLD_UNIT_MAX - CASEFOLD_PREFIX_LEN) / 2)

/* Bits each long-tier payload symbol carries: twelve packs three input bytes
 * into two symbols, so a 255-byte name spends 170 payload symbols and stays
 * far inside the 255-unit budget. The alphabet size and the symbol-count
 * formula both derive from this one constant, so changing the packing moves
 * every consumer together or trips the asserts below.
 */
#define CASEFOLD_SYM_BITS 12u

/* Symbols the long tier spends on a guest name of n bytes: one carrying the
 * length, then one per CASEFOLD_SYM_BITS of payload. Computed in size_t
 * because the result sizes buffers.
 */
#define CASEFOLD_SYMBOLS(n) \
    ((size_t) 1 +           \
     ((size_t) 8 * (n) + CASEFOLD_SYM_BITS - 1) / CASEFOLD_SYM_BITS)

/* Longest host spelling any escaped name can take, in bytes. Each symbol is a
 * BMP code point, so three UTF-8 bytes. Buffers holding a host component must
 * be sized by this and not by NAME_MAX, which is a guest-side limit.
 */
#define CASEFOLD_HOST_NAME_MAX \
    (CASEFOLD_PREFIX_LEN +     \
     (size_t) 3 * CASEFOLD_SYMBOLS(CASEFOLD_GUEST_NAME_MAX))

/* Every escape has to fit the volume's per-name limit, and both tiers spend
 * exactly one unit per output character: the hex tier emits ASCII digits, the
 * long tier BMP code points. The margin is wide today, so the arithmetic is
 * easy to disturb without noticing: raising CASEFOLD_GUEST_NAME_MAX,
 * widening CASEFOLD_PREFIX or shrinking CASEFOLD_SYM_BITS would each push the
 * long tier over, and the volume would then refuse names the guest is entitled
 * to create. Fail the build instead.
 */
_Static_assert(CASEFOLD_PREFIX_LEN + 2 * CASEFOLD_HEX_MAX <= CASEFOLD_UNIT_MAX,
               "hex-tier escape exceeds the per-name UTF-16 unit limit");
_Static_assert(CASEFOLD_PREFIX_LEN +
                       CASEFOLD_SYMBOLS(CASEFOLD_GUEST_NAME_MAX) <=
                   CASEFOLD_UNIT_MAX,
               "long-tier escape exceeds the per-name UTF-16 unit limit");

/* True when @name cannot be stored under its own spelling. That is any name
 * carrying an uppercase ASCII letter or a byte >= 0x80, plus any name that is
 * itself escape-shaped so it cannot be confused with the escape of another
 * name. What is left (lowercase ASCII) is a fixed point of every transformation
 * the volume applies, so two such names never collide.
 */
bool casefold_needs_escape(const char *name);

/* True when @host is a well-formed escape: the prefix, then either an even run
 * of lowercase hex or a run of payload symbols, decoding to a legal component.
 * Total predicate: anything else is an ordinary name that means itself.
 */
bool casefold_is_escaped(const char *host);

/* Write the escaped spelling of @guest into @out.
 *
 * Returns 0, or -1 with errno set: EINVAL for an empty or over-long guest name
 * or one containing '/', ENAMETOOLONG when @out cannot hold the result. Every
 * name Linux can express has an escaped spelling, so ENAMETOOLONG here means
 * the caller's buffer is too small, never that the name cannot be represented.
 */
int casefold_escape(const char *guest, char *out, size_t outsz);

/* Write the guest spelling of the on-disk name @host into @out: the decoded
 * name when @host is escaped, otherwise @host unchanged. Pure and total over
 * real names; the failures are ENAMETOOLONG when @out is too small and EINVAL
 * for a missing argument.
 */
int casefold_to_guest(const char *host, char *out, size_t outsz);
