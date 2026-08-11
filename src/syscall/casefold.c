/*
 * Case-folding filename representation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The encoding itself: which guest names have to be escaped, what their escaped
 * spelling is, and how to read one back. Deliberately free of project
 * dependencies so it links on its own; casefold.h states the contract.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "syscall/casefold.h"

/* Payload alphabet for the long tier: one symbol per CASEFOLD_SYM_BITS value,
 * drawn from the CJK Unified Ideographs starting at U+4E00. The block is
 * chosen because these code points have no case mappings and no canonical or
 * compatibility decompositions, so no two payloads can fold onto each other
 * however aggressive the volume's matching is. Neighboring blocks are not
 * interchangeable: CJK Compatibility Ideographs (U+F900) do normalize, Hangul
 * syllables and dakuten kana decompose, and Cherokee gained case in Unicode 8.
 */
#define CASEFOLD_SYM_BASE 0x4E00u
#define CASEFOLD_SYM_COUNT (1u << CASEFOLD_SYM_BITS)

/* The alphabet must stay inside the ideograph block's uniform run; growing
 * CASEFOLD_SYM_BITS past it would spill symbols into code points with the
 * folding behavior the comment above excludes.
 */
_Static_assert(CASEFOLD_SYM_BASE + CASEFOLD_SYM_COUNT <= 0x9FFFu + 1u,
               "payload alphabet exceeds the CJK Unified Ideographs block");

static bool is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static unsigned hex_value(char c)
{
    return c <= '9' ? (unsigned) (c - '0') : (unsigned) (c - 'a' + 10);
}

bool casefold_needs_escape(const char *name)
{
    if (!name || name[0] == '\0')
        return false;

    for (const unsigned char *p = (const unsigned char *) name; *p; p++) {
        if (*p >= 0x80 || (*p >= 'A' && *p <= 'Z'))
            return true;
    }

    /* A name that already looks like an escape must be escaped too, or reading
     * it back would yield whatever it decodes to instead of itself.
     */
    return casefold_is_escaped(name);
}

/* Read one payload symbol at @p. Returns its value, or -1 when @p does not
 * begin a three-byte sequence inside the payload block.
 */
static int symbol_read(const unsigned char *p)
{
    uint32_t cp;

    if ((p[0] & 0xF0u) != 0xE0u || (p[1] & 0xC0u) != 0x80u ||
        (p[2] & 0xC0u) != 0x80u)
        return -1;
    cp = ((uint32_t) (p[0] & 0x0Fu) << 12) | ((uint32_t) (p[1] & 0x3Fu) << 6) |
         (uint32_t) (p[2] & 0x3Fu);
    if (cp < CASEFOLD_SYM_BASE || cp >= CASEFOLD_SYM_BASE + CASEFOLD_SYM_COUNT)
        return -1;
    return (int) (cp - CASEFOLD_SYM_BASE);
}

static void symbol_write(unsigned char *p, unsigned value)
{
    uint32_t cp = CASEFOLD_SYM_BASE + value;

    p[0] = (unsigned char) (0xE0u | (cp >> 12));
    p[1] = (unsigned char) (0x80u | ((cp >> 6) & 0x3Fu));
    p[2] = (unsigned char) (0x80u | (cp & 0x3Fu));
}

/* One bit of @bytes, MSB first, or 0 past the end. */
static unsigned bit_at(const unsigned char *bytes, size_t len, size_t pos)
{
    if (pos / 8 >= len)
        return 0;
    return (bytes[pos / 8] >> (7 - pos % 8)) & 1u;
}

/* Decode an escaped host name. Returns the decoded length in bytes, or -1 when
 * @host is not a well-formed escape. @out must hold CASEFOLD_GUEST_NAME_MAX
 * bytes; the result is not NUL-terminated here because a decoded name may not
 * be a legal component, which the caller checks.
 */
static int decode_payload(const char *host, unsigned char *out)
{
    const unsigned char *tail;

    if (strncmp(host, CASEFOLD_PREFIX, CASEFOLD_PREFIX_LEN))
        return -1;
    tail = (const unsigned char *) host + CASEFOLD_PREFIX_LEN;
    if (*tail == '\0')
        return -1;

    if (is_hex_digit((char) *tail)) {
        size_t len = strlen((const char *) tail);
        size_t n = len / 2;

        /* Lowercase only, and even length, so each name has exactly one hex
         * spelling. A name long enough for the symbol tier never appears here,
         * which is the other half of that uniqueness.
         */
        if (len % 2 != 0 || n == 0 || n > CASEFOLD_HEX_MAX)
            return -1;
        for (size_t i = 0; i < len; i++) {
            if (!is_hex_digit((char) tail[i]))
                return -1;
        }
        for (size_t i = 0; i < n; i++) {
            out[i] = (unsigned char) ((hex_value((char) tail[i * 2]) << 4) |
                                      hex_value((char) tail[i * 2 + 1]));
        }
        return (int) n;
    }

    /* Symbol tier: the first symbol carries the guest length, so the decode
     * knows exactly how many bytes the payload stands for and an even symbol
     * count is not ambiguous between two lengths.
     */
    uint16_t sym[CASEFOLD_SYMBOLS(CASEFOLD_GUEST_NAME_MAX)];
    size_t nsym = 0;
    const unsigned char *p = tail;

    while (*p) {
        int v;
        if (nsym >= sizeof(sym) / sizeof(sym[0]))
            return -1;
        if (!p[1] || !p[2])
            return -1;
        v = symbol_read(p);
        if (v < 0)
            return -1;
        sym[nsym++] = (uint16_t) v;
        p += 3;
    }

    size_t n = sym[0];
    if (n <= CASEFOLD_HEX_MAX || n > CASEFOLD_GUEST_NAME_MAX)
        return -1;
    if (nsym != CASEFOLD_SYMBOLS(n))
        return -1;

    /* Drain the symbols into bytes, most significant bit first, mirroring the
     * order casefold_escape packs them in. Iterating over symbols rather than
     * over bit positions keeps the read bounded by nsym by construction.
     */
    size_t produced = 0;
    uint32_t acc = 0;
    unsigned acc_bits = 0;

    for (size_t i = 1; i < nsym; i++) {
        acc = (acc << CASEFOLD_SYM_BITS) | sym[i];
        acc_bits += CASEFOLD_SYM_BITS;
        while (acc_bits >= 8 && produced < n) {
            acc_bits -= 8;
            out[produced++] = (unsigned char) ((acc >> acc_bits) & 0xFFu);
        }
        acc &= (1u << acc_bits) - 1u;
    }
    if (produced != n)
        return -1;
    /* Padding past the last byte must be zero, or one name would have several
     * spellings and a listing could show the same file twice.
     */
    if (acc != 0)
        return -1;
    return (int) n;
}

/* A decoded payload only counts as an escape when it names something a
 * directory could actually hold. Otherwise the host name means itself.
 */
static bool decoded_is_legal(const unsigned char *name, size_t len)
{
    if (len == 0 || len > CASEFOLD_GUEST_NAME_MAX)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (name[i] == '/' || name[i] == '\0')
            return false;
    }
    if (len == 1 && name[0] == '.')
        return false;
    if (len == 2 && name[0] == '.' && name[1] == '.')
        return false;
    return true;
}

bool casefold_is_escaped(const char *host)
{
    unsigned char buf[CASEFOLD_GUEST_NAME_MAX];
    int len;

    if (!host)
        return false;
    len = decode_payload(host, buf);
    return len > 0 && decoded_is_legal(buf, (size_t) len);
}

int casefold_escape(const char *guest, char *out, size_t outsz)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *g = (const unsigned char *) guest;
    size_t n;

    if (!guest || !out) {
        errno = EINVAL;
        return -1;
    }
    n = strlen(guest);
    if (n == 0 || n > CASEFOLD_GUEST_NAME_MAX || memchr(guest, '/', n)) {
        errno = EINVAL;
        return -1;
    }
    /* "." and ".." navigate rather than name an entry, so no directory can hold
     * one and an escape standing for one could never be created. Refusing here
     * keeps the codec total: everything it accepts has a real slot to live in.
     */
    if (!strcmp(guest, ".") || !strcmp(guest, "..")) {
        errno = EINVAL;
        return -1;
    }

    if (n <= CASEFOLD_HEX_MAX) {
        size_t need = CASEFOLD_PREFIX_LEN + 2 * n;

        if (need + 1 > outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(out, CASEFOLD_PREFIX, CASEFOLD_PREFIX_LEN);
        for (size_t i = 0; i < n; i++) {
            out[CASEFOLD_PREFIX_LEN + i * 2] = hex[g[i] >> 4];
            out[CASEFOLD_PREFIX_LEN + i * 2 + 1] = hex[g[i] & 0x0Fu];
        }
        out[need] = '\0';
        return 0;
    }

    size_t nsym = CASEFOLD_SYMBOLS(n);
    size_t need = CASEFOLD_PREFIX_LEN + 3 * nsym;

    if (need + 1 > outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, CASEFOLD_PREFIX, CASEFOLD_PREFIX_LEN);
    unsigned char *w = (unsigned char *) out + CASEFOLD_PREFIX_LEN;
    symbol_write(w, (unsigned) n);
    w += 3;
    for (size_t i = 1; i < nsym; i++) {
        unsigned value = 0;
        for (unsigned k = 0; k < CASEFOLD_SYM_BITS; k++) {
            value =
                (value << 1) | bit_at(g, n, (i - 1) * CASEFOLD_SYM_BITS + k);
        }
        symbol_write(w, value);
        w += 3;
    }
    out[need] = '\0';
    return 0;
}

int casefold_to_guest(const char *host, char *out, size_t outsz)
{
    unsigned char buf[CASEFOLD_GUEST_NAME_MAX];
    int len;
    size_t plain;

    if (!host || !out || outsz == 0) {
        errno = EINVAL;
        return -1;
    }

    len = decode_payload(host, buf);
    if (len > 0 && decoded_is_legal(buf, (size_t) len)) {
        if ((size_t) len + 1 > outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(out, buf, (size_t) len);
        out[len] = '\0';
        return 0;
    }

    plain = strlen(host);
    if (plain + 1 > outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, host, plain + 1);
    return 0;
}
