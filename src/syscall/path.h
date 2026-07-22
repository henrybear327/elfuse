/*
 * Shared guest/host path handling
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#include "syscall/internal.h"

typedef enum {
    PATH_TR_NONE = 0,
    PATH_TR_NOFOLLOW = 1u << 0,
    PATH_TR_CREATE = 1u << 1,
    PATH_TR_CREATE_PARENTS = 1u << 2,
} path_translate_flags_t;

typedef struct {
    const char *guest_path;
    const char *intercept_path;
    const char *host_path;
    int proc_resolved;
    bool fuse_path;
    /* Path was rewritten into the /dev/shm host backing dir. Follow-capable
     * callers must force nofollow; see dev_shm_resolve_path() in procemu.c.
     */
    bool is_dev_shm;
    char proc_path[LINUX_PATH_MAX];
    char guest_buf[LINUX_PATH_MAX];
    char host_buf[LINUX_PATH_MAX];
} path_translation_t;

/* Host dirfd for a *at() call on a translated path. A shm redirect gives an
 * absolute host path, so use AT_FDCWD (POSIX ignores dirfd for absolute paths).
 */
static inline host_fd_t path_translation_dirfd(const path_translation_t *tx,
                                               const host_fd_ref_t *ref)
{
    return tx->is_dev_shm ? AT_FDCWD : ref->fd;
}

/* Force AT_SYMLINK_NOFOLLOW on the *at metadata calls for a shm redirect. One
 * choke point for the never-follow invariant; see dev_shm_resolve_path().
 */
static inline int path_translation_at_flags(const path_translation_t *tx,
                                            int at_flags)
{
    return tx->is_dev_shm ? (at_flags | AT_SYMLINK_NOFOLLOW) : at_flags;
}

/* Flags an open(2) of a translated /dev/shm leaf needs, mirroring
 * shm_open_leaf(): O_NOFOLLOW stops a symlink under the synthetic /dev/shm dir
 * from resolving the leaf out of the namespace, and O_NONBLOCK stops a FIFO
 * leaf from parking the vCPU thread on an open with no writer.
 */
static inline int path_translation_oflags(const path_translation_t *tx,
                                          int oflags)
{
    return tx->is_dev_shm ? (oflags | O_NOFOLLOW | O_NONBLOCK) : oflags;
}

/* Advance *pathp to the next '/'-separated component, skipping empty segments
 * from repeated slashes. Returns true with the component (not NUL-terminated)
 * reported through comp and len, leaving *pathp at its end; returns false once
 * only slashes or the terminating NUL remain.
 */
bool path_next_component(const char **pathp, const char **comp, size_t *len);

/* True when the counted component [comp, comp+len) equals the NUL-terminated
 * literal lit. Operates on the non-NUL-terminated component that
 * path_next_component reports, so callers avoid copying into a scratch buffer
 * just to strcmp.
 */
static inline bool path_component_eq(const char *comp,
                                     size_t len,
                                     const char *lit)
{
    size_t n = strlen(lit);
    return len == n && !memcmp(comp, lit, n);
}

/* True when a translated cwd-relative lookup may bypass dirfd resolution and
 * intercept matching and go straight to the host against AT_FDCWD. Callers
 * must pass tx->host_path to the host call, never the raw guest name: under a
 * casefold sysroot a guest-created file exists on disk only under its sidecar
 * token, which the translation already resolved. No sysroot gate is needed
 * because host_path equals the raw name when no rewrite applied.
 */
static inline bool path_translation_relative_fast_path(
    const path_translation_t *tx,
    guest_fd_t dirfd)
{
    return tx->proc_resolved == 0 && !tx->fuse_path &&
           dirfd == LINUX_AT_FDCWD && tx->guest_path[0] != '\0' &&
           tx->guest_path[0] != '/';
}

/* Resolved object of an AT_EMPTY_PATH operation (the dirfd itself, or the
 * current directory for AT_FDCWD). Exactly one of the identities holds:
 * proc_path non-empty (dirfd is an O_PATH fd bound to a synthetic /proc
 * file; ref is also open), fuse_path non-empty (the cwd lies inside a FUSE
 * mount; ref stays closed), fuse_fd true (dirfd itself is FUSE-backed; ref
 * stays closed), or plain host resolution with ref open.
 */
typedef struct {
    host_fd_ref_t ref;
    bool fuse_fd;
    char proc_path[LINUX_PATH_MAX];
    char fuse_path[LINUX_PATH_MAX];
} path_empty_at_t;

/* Resolve an AT_EMPTY_PATH object, surfacing the FUSE and /proc identities
 * that path_translate_at would have applied to a non-empty name as data:
 * callers pick the policy (mutations reject FUSE with ENOSYS and synthetic
 * /proc with EPERM; stat serves both through their interceptors). A dead fd
 * yields -LINUX_EBADF, a failed cwd probe the mapped host errno.
 *
 * On success returns 0; when out->ref was opened the caller must close it
 * on every return path (out->ref.fd is -1 otherwise).
 */
int64_t path_resolve_empty_at(guest_fd_t dirfd, path_empty_at_t *out);

/* Convert a host path to its guest-visible spelling: strips the sysroot
 * prefix and reverse-maps sidecar token components through their directory
 * indices. The only sanctioned host-to-guest converter; prefix arithmetic on
 * host paths leaks token spellings to the guest.
 */
int path_host_to_guest(const char *host_path, char *out, size_t outsz);

bool path_might_use_open_intercept(const char *path);
bool path_might_use_stat_intercept(const char *path);
int path_check_intercept_access(const struct stat *st, int mode, int flags);
int path_translate_at(guest_fd_t dirfd,
                      const char *path,
                      unsigned int flags,
                      path_translation_t *tx);
int path_translate_dirent_name(guest_fd_t dirfd,
                               const char *host_name,
                               char *guest_name,
                               size_t guest_name_sz);
int resolve_proc_at_path(guest_fd_t dirfd,
                         const char *path,
                         char *out,
                         size_t outsz);
int resolve_proc_dirfd_path(guest_fd_t dirfd,
                            const char *path,
                            char *out,
                            size_t outsz);
int sys_path_has_symlink(guest_fd_t dirfd, const char *path);

const char *path_resolve_sysroot_path(const char *path,
                                      char *buf,
                                      size_t bufsz);
const char *path_resolve_sysroot_nofollow_path(const char *path,
                                               char *buf,
                                               size_t bufsz);
const char *path_resolve_sysroot_create_path(const char *path,
                                             char *buf,
                                             size_t bufsz,
                                             bool create_parents);

int path_openat2_stays_beneath(const char *path, bool clamp_at_root);
int path_openat2_normalize_in_root(const char *path, char *out, size_t outsz);
bool path_openat2_is_fd_magiclink_anchor(guest_fd_t dirfd, const char *path);
int path_openat2_resolved_within_root(guest_fd_t dirfd,
                                      const char *path,
                                      uint64_t oflags,
                                      bool in_root);
/* Returns 1 if resolving path against dirfd would cross a mount boundary from
 * the guest's perspective, 0 if it stays inside the same logical filesystem,
 * and -1 with errno set on dirfd lookup failures. Mount classes are: regular
 * guest filesystem, /proc, /dev, /sys, /tmp, /dev/shm, and each live or
 * tombstoned FUSE mount (keyed by mount_id). The walker classifies every
 * intermediate prefix as it advances, so transient excursions through /proc
 * that lexically resolve back into the root class still surface as a crossing.
 * Symlink components are expanded inline against the host-walk fd when possible
 * so a link whose target lives in a different class is caught at the precheck.
 *
 * When out_start_class is non-NULL it is populated with the dirfd's mount class
 * on every non-error return so the caller can re-run the check against the
 * actually opened fd via path_openat2_check_fd_xdev. The post-open check is
 * what closes the symlink bypass for callers that do not also set
 * RESOLVE_NO_SYMLINKS: the precheck's fstatat walk cannot see symlinks that
 * live in a sidecar shadow directory (case-fold sysroot), so the kernel may
 * follow a link the walker did not, and only F_GETPATH on the resulting fd
 * reveals the real landing site.
 *
 * Known gaps (best-effort by design):
 * - host_path_to_guest_path strips the configured sysroot prefix with
 *    a case-sensitive strncmp; on case-insensitive macOS volumes a
 *    differently-cased F_GETPATH could fail to strip and the dirfd is
 *    then classified as the root class. Sidecar tokens in the stripped
 *    remainder are reverse-mapped, but an orphan token with no index row
 *    passes through under its on-disk spelling. Sysroots that happen to
 *    live under /proc, /dev, or /sys on the host are not supported.
 * - A sibling vCPU that chdir(2)s, dup3(2)s over dirfd, or mounts /
 *    unmounts a FUSE filesystem between this check and the subsequent
 *    sys_openat may shift the resolution into a different mount class
 *    without the cross being detected. The race window is narrow and
 *    the guest is in elfuse's trust domain.
 */
int path_openat2_crosses_mount(guest_fd_t dirfd,
                               const char *path,
                               bool in_root,
                               int *out_start_class);

/* Post-open verification for RESOLVE_NO_XDEV. Reads the host-side canonical
 * path of the just-opened guest fd via fcntl(F_GETPATH), strips the sysroot
 * prefix, and classifies the result against the start class captured by
 * path_openat2_crosses_mount.
 *
 * Returns 1 if the resolved fd sits in a different mount class than the
 * resolution started in, 0 if it stays in the same class, -1 with errno set on
 * lookup failures (e.g. fd closed, F_GETPATH refused). Catches the
 * symlink-driven crossings that the string-only precheck misses by design.
 */
int path_openat2_check_fd_xdev(int guest_fd, int start_class);
