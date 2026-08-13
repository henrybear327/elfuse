/*
 * Native-host unit test for absock derived names
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Over-long pathname AF_UNIX socket paths and long abstract names both derive
 * a short filename from a digest, and absock_shorten_path treats a same-named
 * link whose target differs as stale and repoints it. A digest narrow enough
 * to collide in practice therefore aims one socket's live link at another's
 * target, which is cross-socket misdirection, not a cosmetic clash. The old
 * 32-bit tail collides at the birthday bound of ~2^16 names, cheap enough to
 * brute-force below; the 64-bit tail must tell such a pair apart.
 *
 * Code under test: absock_encode_name and absock_link_name in
 * src/syscall/net-absock.c, through the header's unit-test seam; no real
 * volume can be made to produce the collision on demand, so the naming
 * functions are fed directly. A regression narrows the digest or truncates it
 * out of the name.
 *
 * What a pass does not prove: 64-bit collisions still exist at their own
 * birthday bound (~2^32 names); the guarantee bought here is the width, not
 * impossibility.
 *
 * Native macOS binary; no HVF entitlement needed.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "host-test-util.h"
#include "syscall/net-abi.h"
#include "syscall/net-absock.h"
#include "syscall/path.h"

/* Stubs for the translation symbols net-absock.o references. Nothing in the
 * naming functions under test reaches them; fixed answers are enough to link.
 */
int64_t linux_errno(void)
{
    return -22;
}
int linux_to_mac_sockaddr(const void *linux_sa,
                          uint32_t linux_len,
                          struct sockaddr_storage *mac_sa)
{
    (void) linux_sa;
    (void) linux_len;
    (void) mac_sa;
    return -1;
}
int mac_to_linux_sockaddr(const struct sockaddr *mac_sa,
                          socklen_t mac_len,
                          uint8_t *linux_sa,
                          uint32_t linux_buf_len)
{
    (void) mac_sa;
    (void) mac_len;
    (void) linux_sa;
    (void) linux_buf_len;
    return -1;
}
int path_translate_at(guest_fd_t dirfd,
                      const char *path,
                      unsigned int flags,
                      path_translation_t *tx)
{
    (void) dirfd;
    (void) path;
    (void) flags;
    (void) tx;
    return -1;
}
int path_host_to_guest(const char *host_path, char *out, size_t outsz)
{
    (void) host_path;
    (void) out;
    (void) outsz;
    return -1;
}

/* The 32-bit FNV-1a the old tail used, kept here as the collision oracle. */
static uint32_t fnv1a32(const char *s)
{
    uint32_t h = 0x811c9dc5;

    for (; *s; s++) {
        h ^= (uint8_t) *s;
        h *= 0x01000193;
    }
    return h;
}

/* All candidates share this 20-byte prefix, mimicking two sockets under one
 * sysroot: the literal prefix bytes of the derived name are then identical,
 * so the digest tail carries all of the distinction.
 */
#define SHARED_PREFIX "/Shared.Sysroot.Pre/"

typedef struct {
    uint32_t hash;
    uint32_t idx;
} cand_t;

static int cand_cmp(const void *a, const void *b)
{
    const cand_t *ca = a, *cb = b;

    if (ca->hash != cb->hash)
        return ca->hash < cb->hash ? -1 : 1;
    return ca->idx < cb->idx ? -1 : 1;
}

static void spell_candidate(uint32_t idx, char *out, size_t outsz)
{
    /* The variable-length pad matters: candidates differing only in a short
     * fixed-position window stay collision-free far past the birthday bound,
     * because FNV-1a mixes so little that the window maps near-injectively.
     * Varying the length moves every later byte's position instead. The
     * shortest candidate is still well past the hex tier, so the digest
     * branch is the one exercised.
     */
    char pad[24];
    size_t pad_len = idx % 23;

    memset(pad, 'x', pad_len);
    pad[pad_len] = '\0';
    snprintf(out, outsz,
             SHARED_PREFIX "Very.Long.Socket.Directory.Chain/%s/sock-%x.Sock",
             pad, idx);
}

/* Find two distinct strings, sharing the 20-byte prefix, whose 32-bit FNV-1a
 * over the whole string collides. ~2^16 uniformly hashed candidates reach the
 * birthday bound; 400k found one at ~207k when this was written, so failing
 * to find one signals the generator regressed, not bad luck.
 */
static bool find_fnv32_collision(char *a, char *b, size_t bufsz)
{
    enum { CANDIDATES = 400000 };
    cand_t *c = malloc(sizeof(cand_t) * CANDIDATES);

    if (!c)
        return false;
    for (uint32_t i = 0; i < CANDIDATES; i++) {
        char s[256];

        spell_candidate(i, s, sizeof(s));
        c[i].hash = fnv1a32(s);
        c[i].idx = i;
    }
    qsort(c, CANDIDATES, sizeof(cand_t), cand_cmp);
    for (uint32_t i = 1; i < CANDIDATES; i++) {
        if (c[i].hash == c[i - 1].hash) {
            spell_candidate(c[i - 1].idx, a, bufsz);
            spell_candidate(c[i].idx, b, bufsz);
            free(c);
            return true;
        }
    }
    free(c);
    return false;
}

int main(void)
{
    /* Worst-case directory spelling: a 20-digit namespace id. */
    static const char dir[] = "/tmp/elfuse-absock-18446744073709551615";
    char a[256], b[256];
    char name_a[104], name_b[104];

    printf("test-absock-names-host: derived socket names\n");

    host_check(find_fnv32_collision(a, b, sizeof(a)), "collision search",
               "no 32-bit collision in 400k candidates");
    host_check(!strncmp(a, b, 20) && strcmp(a, b), "collision pair",
               "pair must share 20 bytes and differ");

    /* The pair defeats a 32-bit tail by construction; the encoded names must
     * still differ.
     */
    absock_encode_name(dir, (const uint8_t *) a, (uint32_t) strlen(a), name_a,
                       sizeof(name_a));
    absock_encode_name(dir, (const uint8_t *) b, (uint32_t) strlen(b), name_b,
                       sizeof(name_b));
    host_check(strcmp(name_a, name_b), "encode collision",
               "32-bit-colliding names must encode differently");
    host_check(strlen(name_a) < 104, "encode budget",
               "encoded name must fit sun_path");

    host_check(absock_link_name(dir, a, name_a, sizeof(name_a)) == 0 &&
                   absock_link_name(dir, b, name_b, sizeof(name_b)) == 0,
               "link naming", "link name derivation failed");
    host_check(strcmp(name_a, name_b), "link collision",
               "32-bit-colliding paths must derive distinct links");
    host_check(strlen(name_a) < 104, "link budget",
               "link name must fit sun_path");

    /* Pid scoping: the marker that makes every exit-time unlink provably of
     * the process's own property.
     */
    {
        char marker[32];

        snprintf(marker, sizeof(marker), "/p%d-", (int) getpid());
        host_check(strstr(name_a, marker) != NULL, "pid scope",
                   "link name must embed the minting pid");
    }

    /* The digest never truncates: with a tight buffer the literal prefix
     * gives way, and the 16-hex-digit tail survives in full.
     */
    {
        char tight[64];

        host_check(absock_link_name(dir, a, tight, sizeof(tight)) == 0 &&
                       strlen(tight) >= 16,
                   "tight budget", "digest must survive a tight buffer");
        host_check(strspn(tight + strlen(tight) - 16, "0123456789abcdef") == 16,
                   "digest tail", "last 16 chars must be the hex digest");
    }

    {
        char fit[104];
        size_t budget = (sizeof(fit) - strlen(dir) - 2) / 2;
        /* Spelled from the budget so the hex capacity is exactly even: an odd
         * capacity can never equal an even hex length, and the equality is
         * the boundary being pinned.
         */
        size_t out_sz = strlen(dir) + 2 + budget * 2;
        uint8_t raw[104] = {0};

        absock_encode_name(dir, raw, (uint32_t) budget, fit, out_sz);
        host_check(strlen(fit) == strlen(dir) + 1 + budget * 2,
                   "literal arm boundary",
                   "a name at the hex budget must encode literally");
        absock_encode_name(dir, raw, (uint32_t) budget + 1, fit, out_sz);
        host_check(strspn(fit + strlen(fit) - 16, "0123456789abcdef") == 16,
                   "digest arm boundary",
                   "one byte past the budget must take the digest arm");
    }

    return host_summary("test-absock-names-host");
}
