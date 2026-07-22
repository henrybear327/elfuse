/*
 * Abstract AF_UNIX emulation helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

int absock_is_abstract_unix(const uint8_t *linux_sa, uint32_t addrlen);

/* Convert a guest sockaddr to the host form. Pathname AF_UNIX addresses go
 * through sysroot path translation (create semantics for bind, lookup for
 * connect/sendto/sendmsg), with over-long translated paths diverted through
 * a short symlink in the private absock dir; every other family delegates to
 * linux_to_mac_sockaddr. Returns the mac sockaddr length, or a negative
 * LINUX errno usable directly as the syscall result.
 */
int net_sockaddr_to_mac(const uint8_t *linux_sa,
                        uint32_t addrlen,
                        bool create,
                        struct sockaddr_storage *mac_sa);

/* Convert a host sockaddr back to the guest form. Pathname AF_UNIX
 * addresses are reverse-mapped through path_host_to_guest (undoing the
 * over-length shortening symlink first) so the guest reads back the
 * spelling it bound or connected with; every other family delegates to
 * mac_to_linux_sockaddr. Same return convention as mac_to_linux_sockaddr.
 */
int net_sockaddr_from_mac(const struct sockaddr *mac_sa,
                          uint32_t mac_len,
                          uint8_t *linux_sa,
                          uint32_t linux_sa_size);
int absock_rewrite_connect(const uint8_t *linux_sa,
                           uint32_t addrlen,
                           struct sockaddr_storage *mac_sa);
int absock_bind_prepare(const uint8_t *linux_sa,
                        uint32_t addrlen,
                        struct sockaddr_storage *mac_sa,
                        int guest_fd,
                        int *out_len);
void absock_bind_commit(int idx);
void absock_bind_rollback(int idx);
int absock_reverse_lookup(const char *fs_path,
                          uint8_t *out_name,
                          uint32_t *out_len);
