/*
 * Case-folding fallback VFS helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#include "syscall/internal.h"

#define SIDECAR_INDEX_NAME ".elfuse_case_index"
#define SIDECAR_TOKEN_PREFIX ".ef_"
#define SIDECAR_TOKEN_HEX_LEN 16
#define SIDECAR_TOKEN_NAME_LEN (4 + SIDECAR_TOKEN_HEX_LEN)
#define SIDECAR_NOT_HANDLED ((int64_t) INT64_MIN)

bool sidecar_active(void);
bool sidecar_name_reserved(const char *name);
bool sidecar_name_is_token(const char *name, size_t len);
bool sidecar_path_targets_reserved_name(const char *path);
int sidecar_translate_lookup_at(guest_fd_t dirfd,
                                const char *path,
                                char *out,
                                size_t outsz);
int sidecar_translate_dirent_name(guest_fd_t dirfd,
                                  const char *host_name,
                                  char *guest_name,
                                  size_t guest_name_sz);
/* Same mapping for callers that already hold the directory's host fd (e.g.
 * inotify snapshots), skipping the guest fd-table resolution.
 */
int sidecar_translate_dirent_name_hostfd(host_fd_t dir_host_fd,
                                         const char *host_name,
                                         char *guest_name,
                                         size_t guest_name_sz);

/* A directory's name mapping, held open across a whole readdir pass so the
 * on-disk index is read and parsed once instead of once per entry. The one-shot
 * calls above are this opened, queried, and closed again, which costs a file
 * read per entry when a directory is full of tokens. The handle is opaque so
 * the index representation stays private.
 *
 * sidecar_dir_map_open() returns 0 on success and -1 when the directory has an
 * index that cannot be read, which callers must treat as a failure of the whole
 * pass rather than as an empty mapping. On success *map may still be NULL,
 * which means there is nothing to map (the sidecar is inert, or the directory
 * has no index at all); that NULL is safe to pass to the calls below, where
 * every name then maps to itself.
 */
typedef struct sidecar_dir_map sidecar_dir_map_t;

int sidecar_dir_map_open(host_fd_t dir_host_fd, sidecar_dir_map_t **map);
void sidecar_dir_map_close(sidecar_dir_map_t *map);

/* Map one entry name from this directory. Returns 1 when the entry is sidecar
 * bookkeeping and the caller must skip it, 0 otherwise. On 0, guest_name holds
 * the guest spelling, or is left empty when the name is a token with no index
 * row (an orphan, which callers hide rather than expose).
 */
int sidecar_dir_map_name(const sidecar_dir_map_t *map,
                         const char *host_name,
                         char *guest_name,
                         size_t guest_name_sz);
int sidecar_reverse_map_host_path(const char *sysroot,
                                  const char *host_rel,
                                  char *out,
                                  size_t outsz);
int sidecar_openat(guest_fd_t dirfd,
                   const char *path,
                   int linux_flags,
                   mode_t mode);
int64_t sidecar_mkdirat(guest_fd_t dirfd, const char *path, mode_t mode);
int64_t sidecar_unlinkat(guest_fd_t dirfd, const char *path, int flags);
int64_t sidecar_linkat(guest_fd_t olddirfd,
                       const char *oldpath,
                       guest_fd_t newdirfd,
                       const char *newpath,
                       int flags);
int64_t sidecar_renameat(guest_fd_t olddirfd,
                         const char *oldpath,
                         guest_fd_t newdirfd,
                         const char *newpath,
                         int flags);
