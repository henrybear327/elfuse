/* elfuse VM launch entry: post-CLI bring-up + run loop + teardown
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse_launch is the single entry point for "run a guest binary in a
 * fresh HVF VM until it exits". It is shared between main() (legacy
 * positional-ELF CLI) and future launchers such as the OCI run helper.
 *
 * The function owns the guest_t, the vCPU, the GDB stub, the run loop, the
 * diagnostic dumps, and guest teardown; it does NOT own the elf_path /
 * sysroot / guest_argv heap copies or the sysroot_mount the host CLI may
 * have provisioned. Those stay with the caller so behaviors that need the
 * original CLI argv (proctitle rewriting, --create-sysroot detach on exit,
 * host cwd save+restore) stay coherent however the launch was kicked off.
 *
 * The caller owns every pointer in launch_args_t for the duration of the
 * call; elfuse_launch reads but never frees them. Per-field lifetime and
 * ownership notes live on the struct members below.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    /* Host path to the guest ELF; may be a FUSE-materialized temp when
     * elf_host_temp is set.
     */
    const char *elf_path;

    /* elf_path is a FUSE-materialized temp to unlink once
     * guest_bootstrap_prepare has loaded it (kept for Rosetta guests, which
     * reopen the path). The caller owns the unlink on any pre-prepare
     * failure; elfuse_launch owns it from the prepare call onward.
     */
    bool elf_host_temp;

    /* Host filesystem path to the sysroot the guest sees as / (absolute),
     * or NULL when the guest runs without a sysroot.
     */
    const char *sysroot;

    /* Argv the guest sees. guest_argv[0] is the guest-visible entrypoint
     * path (what the guest reads back via /proc/self/exe and argv[0]); it
     * differs from elf_path (the resolved host path) under path translation
     * or a FUSE-materialized temp.
     */
    int guest_argc;
    const char **guest_argv;

    /* NULL-terminated guest environ. NULL means "use host environ". envp is
     * char** (not const) to match the environ/guest_bootstrap_prepare
     * convention: guest programs may mutate their environment.
     */
    char **envp;

    /* When true, stage uid/gid as the guest identity before bring-up so the
     * auxv AT_UID/AT_GID snapshot and getuid()/getgid() agree. When false,
     * uid/gid are ignored and the guest runs under the compile-time default
     * GUEST_UID/GUEST_GID (0 under fakeroot), NOT the host identity; a
     * launcher that wants the host identity must set has_creds and pass
     * getuid()/getgid().
     */
    bool has_creds;
    uint32_t uid, gid;

    /* Guest-absolute initial working directory. NULL inherits the host
     * cwd (the caller may chdir first to control it).
     */
    const char *cwd_guest;

    /* GDB Remote Serial Protocol port (0 disables the stub) and whether
     * to halt before the first guest instruction.
     */
    int gdb_port;
    bool gdb_stop_on_entry;

    /* Per-iteration vCPU run timeout. 0 disables (no alarm()). */
    int timeout_sec;

    bool verbose;
} launch_args_t;

/* Bring up the guest VM, run it to exit / signal / timeout, tear down,
 * return the exit code. Returns 1 on bring-up failure (with a log
 * message) and the guest's exit status otherwise.
 */
int elfuse_launch(const launch_args_t *args);
