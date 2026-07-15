/* elfuse VM launch entry: post-CLI bring-up + run loop + teardown
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse_launch is the single entry point for "run a guest binary in a
 * fresh HVF VM until it exits". It is shared between main() (legacy
 * positional-ELF CLI) and future launchers such as the OCI run helper.
 *
 * The function owns the guest_t, the vCPU, the GDB stub, the run loop,
 * the diagnostic dumps, and guest teardown; it does NOT own the
 * elf_path / sysroot / guest_argv heap copies or the sysroot_mount the
 * host CLI may have provisioned; those stay with the caller so
 * behaviors that need the original CLI argv (proctitle rewriting,
 * --create-sysroot detach on exit, host cwd save+restore) remain
 * coherent regardless of how the launch was kicked off.
 *
 * Lifetime / ownership contract:
 *
 *   - The caller owns every pointer in launch_args_t. elfuse_launch reads
 *     them and does not free them; const-qualified pointers stay valid
 *     for the duration of the call.
 *   - envp may be NULL; the host process environ is used in that case.
 *   - guest_argv is the string array the guest sees as its argv.
 *     guest_argv[0] is the guest-visible entrypoint path (what the guest
 *     reads back via /proc/self/exe and argv[0]); elf_path is the
 *     resolved host path to that binary. The two differ when path
 *     translation or a FUSE-materialized temp is involved.
 *   - elf_host_temp is true when elf_path is a FUSE-materialized temp
 *     that must be unlinked once guest_bootstrap_prepare has loaded it
 *     (skipped for Rosetta guests, which reopen the path). The caller
 *     owns the unlink for any pre-prepare failure; elfuse_launch owns it
 *     from the prepare call onward.
 *   - fork_child_fd / vfork_notify_fd are forwarded for fork-child-routed
 *     launches; main() dispatches the fork-child path before reaching
 *     elfuse_launch and so passes -1.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    /* Host filesystem path to the guest ELF (resolved; may be a
     * FUSE-materialized temp when elf_host_temp is true).
     */
    const char *elf_path;

    /* True when elf_path is a temp to unlink after guest_bootstrap_prepare
     * loads it.
     */
    bool elf_host_temp;

    /* Host filesystem path to the sysroot the guest sees as / (absolute),
     * or NULL when the guest runs without a sysroot.
     */
    const char *sysroot;

    /* String array the guest sees as its argv. guest_argv[0] is the
     * guest-visible entrypoint path.
     */
    int guest_argc;
    const char **guest_argv;

    /* NULL-terminated guest environ. NULL means "use host environ". envp is
     * char** (not const) to match the environ/guest_bootstrap_prepare
     * convention: guest programs may mutate their environment.
     */
    char **envp;

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
