/*
 * Abstract AF_UNIX emulation helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dirent.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "utils.h"

#include "syscall/abi.h"
#include "syscall/internal.h"
#include "syscall/net.h"
#include "syscall/net-abi.h"
#include "syscall/net-absock.h"
#include "syscall/path.h"

#define ABSOCK_MAX_ENTRIES 64
#define ABSOCK_MAX_NAME 107
/* Linux struct sockaddr_un carries at most 108 sun_path bytes. */
#define LINUX_UNIX_PATH_MAX 108

typedef struct {
    int guest_fd;
    uint8_t name[ABSOCK_MAX_NAME];
    uint32_t name_len;
    char fs_path[104];
    bool active;
} absock_entry_t;

static pthread_mutex_t absock_lock = PTHREAD_MUTEX_INITIALIZER;
static absock_entry_t absock_table[ABSOCK_MAX_ENTRIES];
static char absock_dir[128];
static bool absock_dir_created;
static _Atomic uint64_t absock_namespace_id;
static _Atomic uint32_t absock_autobind_counter;

static void absock_cleanup(void);

static int absock_ensure_dir_locked(void)
{
    uint64_t namespace_id = atomic_load(&absock_namespace_id);

    if (absock_dir_created)
        return 0;

    if (namespace_id == 0) {
        namespace_id = (uint64_t) getpid();
        atomic_store(&absock_namespace_id, namespace_id);
    }
    snprintf(absock_dir, sizeof(absock_dir), "/tmp/elfuse-absock-%llu",
             (unsigned long long) namespace_id);
    /* The namespace-id path is guessable; create_private_dir rejects a
     * pre-planted symlink or foreign-owned directory in world-writable /tmp.
     */
    if (create_private_dir(absock_dir) < 0)
        return -1;

    /* Arm the exit sweep here, the one point where on-disk namespace state
     * first appears. Every producer of that state (abstract bind, autobind,
     * connect rewrite, and the pathname-socket shortening links) reaches the
     * dir through this function, so a single registration covers them all.
     */
    static bool cleanup_registered;
    if (!cleanup_registered) {
        atexit(absock_cleanup);
        cleanup_registered = true;
    }

    absock_dir_created = true;
    return 0;
}

uint64_t absock_get_namespace_id(void)
{
    uint64_t namespace_id = atomic_load(&absock_namespace_id);
    if (namespace_id == 0)
        return (uint64_t) getpid();
    return namespace_id;
}

void absock_set_namespace_id(uint64_t namespace_id)
{
    if (namespace_id == 0)
        namespace_id = (uint64_t) getpid();
    atomic_store(&absock_namespace_id, namespace_id);
}

static void absock_encode_name(const uint8_t *name,
                               uint32_t len,
                               char *out,
                               size_t out_sz)
{
    size_t dir_len = strlen(absock_dir);
    size_t max_hex = out_sz - dir_len - 2;
    size_t hex_needed = (size_t) len * 2;

    size_t pos = (size_t) snprintf(out, out_sz, "%s/", absock_dir);
    if (hex_needed <= max_hex) {
        for (uint32_t i = 0; i < len && pos + 2 < out_sz; i++)
            pos += (size_t) snprintf(out + pos, out_sz - pos, "%02x", name[i]);
    } else {
        uint32_t prefix_bytes = 20;
        if (prefix_bytes > len)
            prefix_bytes = len;
        for (uint32_t i = 0; i < prefix_bytes && pos + 2 < out_sz; i++)
            pos += (size_t) snprintf(out + pos, out_sz - pos, "%02x", name[i]);
        uint32_t h = 0x811c9dc5;
        for (uint32_t i = 0; i < len; i++) {
            h ^= name[i];
            h *= 0x01000193;
        }
        snprintf(out + pos, out_sz - pos, "%08x", h);
    }
}

static const char *absock_lookup_locked(const uint8_t *name, uint32_t name_len)
{
    for (int i = 0; i < ABSOCK_MAX_ENTRIES; i++) {
        if (absock_table[i].active && absock_table[i].name_len == name_len &&
            !memcmp(absock_table[i].name, name, name_len)) {
            return absock_table[i].fs_path;
        }
    }
    return NULL;
}

static int absock_register_locked(int guest_fd,
                                  const uint8_t *name,
                                  uint32_t name_len,
                                  char *fs_path_out,
                                  size_t fs_path_sz)
{
    for (int i = 0; i < ABSOCK_MAX_ENTRIES; i++) {
        if (!absock_table[i].active) {
            absock_table[i].guest_fd = guest_fd;
            absock_table[i].name_len = name_len;
            memcpy(absock_table[i].name, name, name_len);
            absock_encode_name(name, name_len, absock_table[i].fs_path,
                               sizeof(absock_table[i].fs_path));
            if (fs_path_out)
                snprintf(fs_path_out, fs_path_sz, "%s",
                         absock_table[i].fs_path);
            return i;
        }
    }
    return -1;
}

void absock_unregister_fd(int guest_fd)
{
    pthread_mutex_lock(&absock_lock);
    for (int i = 0; i < ABSOCK_MAX_ENTRIES; i++) {
        if (absock_table[i].active && absock_table[i].guest_fd == guest_fd) {
            unlink(absock_table[i].fs_path);
            absock_table[i].active = false;
        }
    }
    pthread_mutex_unlock(&absock_lock);
}

int absock_reverse_lookup(const char *fs_path,
                          uint8_t *out_name,
                          uint32_t *out_len)
{
    pthread_mutex_lock(&absock_lock);
    for (int i = 0; i < ABSOCK_MAX_ENTRIES; i++) {
        if (absock_table[i].active &&
            !strcmp(absock_table[i].fs_path, fs_path)) {
            *out_len = absock_table[i].name_len;
            memcpy(out_name, absock_table[i].name, absock_table[i].name_len);
            pthread_mutex_unlock(&absock_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&absock_lock);
    return 0;
}

int absock_is_abstract_unix(const uint8_t *linux_sa, uint32_t addrlen)
{
    if (addrlen < 4)
        return 0;
    uint16_t fam;
    memcpy(&fam, linux_sa, 2);
    if (fam != LINUX_AF_UNIX)
        return 0;
    return linux_sa[2] == '\0';
}

static int absock_build_sun(const char *fs_path,
                            struct sockaddr_storage *mac_sa)
{
    struct sockaddr_un *sun = (struct sockaddr_un *) mac_sa;
    memset(sun, 0, sizeof(*sun));
    sun->sun_len = sizeof(*sun);
    sun->sun_family = AF_UNIX;
    size_t path_len = strlen(fs_path);
    if (path_len >= sizeof(sun->sun_path))
        return -1;
    memcpy(sun->sun_path, fs_path, path_len + 1);
    return (int) (offsetof(struct sockaddr_un, sun_path) + path_len + 1);
}

/* Point a short symlink in the private absock dir at an over-long translated
 * socket path so it fits sun_path. bind(2) through a dangling symlink creates
 * the socket at the target and connect(2) follows it (probed on macOS 15).
 * Forked guests share the namespace dir, so a losing EEXIST race is accepted
 * when the existing link already names the same target.
 */
static int absock_shorten_path(const char *host_path, char *out, size_t out_sz)
{
    pthread_mutex_lock(&absock_lock);
    if (absock_ensure_dir_locked() < 0) {
        pthread_mutex_unlock(&absock_lock);
        return -1;
    }
    absock_encode_name((const uint8_t *) host_path,
                       (uint32_t) strlen(host_path), out, out_sz);
    /* Create-first, never unlink a matching link: absock_lock is
     * per-process, so an unconditional unlink could yank a forked sibling's
     * just-created link between its shorten and its bind(2). The encoded
     * name is derived from the target, so an existing link with the same
     * name almost always already points at the right place.
     */
    if (symlink(host_path, out) < 0) {
        char existing[LINUX_PATH_MAX];
        ssize_t n = -1;
        if (errno == EEXIST)
            n = readlink(out, existing, sizeof(existing) - 1);
        if (n < 0 || (size_t) n != strlen(host_path) ||
            /* cppcheck-suppress legacyUninitvar
             * Short-circuit || guarantees memcmp only runs when n ==
             * strlen(host_path) and readlink filled exactly
             * existing[0..n-1] on success.
             */
            memcmp(existing, host_path, (size_t) n)) {
            /* Stale or foreign entry under our name: replace it. */
            (void) unlink(out);
            if (symlink(host_path, out) < 0) {
                pthread_mutex_unlock(&absock_lock);
                return -1;
            }
        }
    }
    pthread_mutex_unlock(&absock_lock);
    return 0;
}

/* Reverse-map one returned pathname AF_UNIX address to its guest spelling.
 * Returns the Linux sockaddr length when the address was rewritten, or -1
 * when it is not a translated pathname and the generic converter should run.
 */
static int absock_sockaddr_un_from_mac(const struct sockaddr_un *sun,
                                       uint32_t mac_len,
                                       uint8_t *linux_sa,
                                       uint32_t linux_sa_size)
{
    /* Bound every read by mac_len: macOS may fill all 104 sun_path bytes
     * with no terminator, and only mac_len bytes of the caller's
     * sockaddr_storage are initialized.
     */
    size_t sp_max = mac_len - offsetof(struct sockaddr_un, sun_path);
    if (sp_max > sizeof(sun->sun_path))
        sp_max = sizeof(sun->sun_path);
    size_t sp_len = strnlen(sun->sun_path, sp_max);
    if (sp_len == 0)
        return -1;
    char mac_path[sizeof(sun->sun_path) + 1];
    memcpy(mac_path, sun->sun_path, sp_len);
    mac_path[sp_len] = '\0';

    /* Undo the over-length shortening symlink, then map the host path back
     * to the guest namespace so the guest reads back the spelling it bound
     * or connected with, not the sysroot-prefixed (and possibly
     * token-bearing) host path.
     */
    char host_path[LINUX_PATH_MAX];
    str_copy_trunc(host_path, mac_path, sizeof(host_path));
    pthread_mutex_lock(&absock_lock);
    bool in_absock_dir = absock_dir_created &&
                         !strncmp(host_path, absock_dir, strlen(absock_dir));
    pthread_mutex_unlock(&absock_lock);
    if (in_absock_dir) {
        char target[LINUX_PATH_MAX];
        ssize_t n = readlink(host_path, target, sizeof(target) - 1);
        if (n > 0) {
            target[n] = '\0';
            str_copy_trunc(host_path, target, sizeof(host_path));
        }
    }

    char guest_path[LINUX_PATH_MAX];
    if (path_host_to_guest(host_path, guest_path, sizeof(guest_path)) != 0 ||
        !strcmp(guest_path, mac_path))
        return -1;

    /* Write the Linux sockaddr directly: the guest may have bound a
     * Linux-legal name longer than the 103 usable bytes of a macOS
     * sun_path, and rebuilding a mac sockaddr first would fail for exactly
     * the paths the shortening symlink serves.
     */
    size_t glen = strlen(guest_path);
    if (glen > LINUX_UNIX_PATH_MAX || linux_sa_size < 2)
        return -1;
    uint16_t fam16 = LINUX_AF_UNIX;
    memcpy(linux_sa, &fam16, 2);
    uint32_t avail = linux_sa_size - 2;
    uint32_t copy = (uint32_t) glen;
    if (glen < LINUX_UNIX_PATH_MAX)
        copy++; /* include the terminator, kernel-style */
    if (copy > avail)
        copy = avail;
    memcpy(linux_sa + 2, guest_path, copy);
    return (int) (2 + copy);
}

int net_sockaddr_from_mac(const struct sockaddr *mac_sa,
                          uint32_t mac_len,
                          uint8_t *linux_sa,
                          uint32_t linux_sa_size)
{
    if (mac_sa && mac_len > offsetof(struct sockaddr_un, sun_path) &&
        mac_sa->sa_family == AF_UNIX) {
        int rc =
            absock_sockaddr_un_from_mac((const struct sockaddr_un *) mac_sa,
                                        mac_len, linux_sa, linux_sa_size);
        if (rc >= 0)
            return rc;
    }
    return mac_to_linux_sockaddr(mac_sa, (socklen_t) mac_len, linux_sa,
                                 linux_sa_size);
}

int net_sockaddr_to_mac(const uint8_t *linux_sa,
                        uint32_t addrlen,
                        bool create,
                        struct sockaddr_storage *mac_sa)
{
    uint16_t fam = 0;
    if (addrlen >= 2)
        memcpy(&fam, linux_sa, 2);

    if (fam == LINUX_AF_UNIX && addrlen > 2 && linux_sa[2] != '\0') {
        /* Pathname socket: the name is a filesystem path and must go through
         * sysroot translation like every other path-taking syscall; the raw
         * bytes would name the unrelated host-literal file. Linux permits an
         * unterminated sun_path, so bound the copy by addrlen.
         */
        char guest_path[LINUX_UNIX_PATH_MAX + 1];
        uint32_t plen = addrlen - 2;
        if (plen > LINUX_UNIX_PATH_MAX)
            return -LINUX_EINVAL;
        memcpy(guest_path, linux_sa + 2, plen);
        guest_path[plen] = '\0';

        /* Creates resolve the parent through the lookup walk and reattach
         * the leaf: PATH_TR_CREATE skips the sidecar, so a bind inside a
         * guest-created (tokenized) directory would miss the on-disk parent.
         * The socket itself keeps its real name; socket names are not
         * tokenized. "/name" and bare relative names have no tokenizable
         * parent and translate whole.
         */
        char *leaf = create ? strrchr(guest_path, '/') : NULL;
        if (leaf == guest_path)
            leaf = NULL;
        if (leaf)
            *leaf = '\0';
        path_translation_t tx;
        if (path_translate_at(LINUX_AT_FDCWD, guest_path,
                              (create && !leaf) ? PATH_TR_CREATE : PATH_TR_NONE,
                              &tx) < 0)
            return linux_errno();
        if (tx.fuse_path || tx.proc_resolved != 0)
            return -LINUX_ENOSYS;
        char joined[LINUX_PATH_MAX];
        const char *host_path = tx.host_path;
        if (leaf) {
            int jn = snprintf(joined, sizeof(joined), "%s/%s", tx.host_path,
                              leaf + 1);
            if (jn < 0 || (size_t) jn >= sizeof(joined))
                return -LINUX_ENAMETOOLONG;
            host_path = joined;
        }

        char short_path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
        if (strlen(host_path) >= sizeof(((struct sockaddr_un *) 0)->sun_path)) {
            /* Surface the real failure (EACCES, EIO, ENOSPC, ...): the guest
             * name is Linux-legal, so reporting ENAMETOOLONG would misattribute
             * a symlink-layer error to the pathname length.
             */
            if (absock_shorten_path(host_path, short_path, sizeof(short_path)) <
                0)
                return linux_errno();
            host_path = short_path;
        }
        int mac_len = absock_build_sun(host_path, mac_sa);
        if (mac_len < 0)
            return -LINUX_ENAMETOOLONG;
        return mac_len;
    }

    int mac_len = linux_to_mac_sockaddr(linux_sa, addrlen, mac_sa);
    return mac_len < 0 ? -LINUX_EINVAL : mac_len;
}

int absock_rewrite_connect(const uint8_t *linux_sa,
                           uint32_t addrlen,
                           struct sockaddr_storage *mac_sa)
{
    const uint8_t *abs_name = linux_sa + 3;
    uint32_t abs_len = addrlen - 3;
    if (abs_len > ABSOCK_MAX_NAME)
        abs_len = ABSOCK_MAX_NAME;

    pthread_mutex_lock(&absock_lock);
    const char *fs_path = absock_lookup_locked(abs_name, abs_len);
    char path_buf[104];
    if (!fs_path) {
        if (absock_ensure_dir_locked() < 0) {
            pthread_mutex_unlock(&absock_lock);
            return -1;
        }
        absock_encode_name(abs_name, abs_len, path_buf, sizeof(path_buf));
        fs_path = path_buf;
    }
    int ret = absock_build_sun(fs_path, mac_sa);
    pthread_mutex_unlock(&absock_lock);
    return ret;
}

int absock_bind_prepare(const uint8_t *linux_sa,
                        uint32_t addrlen,
                        struct sockaddr_storage *mac_sa,
                        int guest_fd,
                        int *out_len)
{
    uint8_t name_buf[ABSOCK_MAX_NAME];
    const uint8_t *abs_name;
    uint32_t abs_len;

    if (addrlen <= 3) {
        uint32_t seq = absock_autobind_counter++;
        abs_len = (uint32_t) snprintf((char *) name_buf, sizeof(name_buf),
                                      "%05x", seq);
        abs_name = name_buf;
    } else {
        abs_name = linux_sa + 3;
        abs_len = addrlen - 3;
        if (abs_len > ABSOCK_MAX_NAME)
            return -1;
    }

    pthread_mutex_lock(&absock_lock);
    if (absock_ensure_dir_locked() < 0) {
        pthread_mutex_unlock(&absock_lock);
        return -1;
    }
    if (absock_lookup_locked(abs_name, abs_len)) {
        pthread_mutex_unlock(&absock_lock);
        return -2;
    }

    char fs_path[104];
    int idx = absock_register_locked(guest_fd, abs_name, abs_len, fs_path,
                                     sizeof(fs_path));
    pthread_mutex_unlock(&absock_lock);
    if (idx < 0)
        return -1;

    *out_len = absock_build_sun(fs_path, mac_sa);
    if (*out_len < 0)
        return -1;
    return idx;
}

void absock_bind_commit(int idx)
{
    pthread_mutex_lock(&absock_lock);
    absock_table[idx].active = true;
    pthread_mutex_unlock(&absock_lock);
}

void absock_bind_rollback(int idx)
{
    pthread_mutex_lock(&absock_lock);
    absock_table[idx].name_len = 0;
    absock_table[idx].guest_fd = -1;
    pthread_mutex_unlock(&absock_lock);
}

static void absock_cleanup(void)
{
    /* Every process unlinks its own table-tracked sockets: those are bound
     * per-process and never shared with a forked sibling.
     */
    for (int i = 0; i < ABSOCK_MAX_ENTRIES; i++) {
        if (absock_table[i].active)
            unlink(absock_table[i].fs_path);
    }

    /* The namespace dir and its untracked shortening links are shared across a
     * forked guest tree (children inherit the root's namespace id), so only the
     * process that minted the namespace sweeps them: a sibling sweeping on its
     * own exit would yank links a live sibling still needs, degrading that
     * sibling's getsockname to the raw host link path. If the root exits first,
     * a live child's reverse map degrades the same way (never corruption) until
     * it recreates the link. See docs/sysroot.md for the full lifecycle.
     */
    if (absock_dir_created &&
        (uint64_t) getpid() == absock_get_namespace_id()) {
        DIR *d = opendir(absock_dir);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                    continue;
                unlinkat(dirfd(d), de->d_name, 0);
            }
            closedir(d);
        }
        rmdir(absock_dir);
    }
}
