/*
 * Run aarch64-linux ELF binaries on macOS Apple Silicon
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Uses Hypervisor.framework to create a lightweight VM with:
 *   - A minimal EL1 shim (embedded as shim_blob.h) that provides exception
 *     vectors and forwards SVC #0 (Linux syscalls) to the host via HVC #5.
 *   - All system registers configured from the host before vCPU start.
 *   - Guest memory identity-mapped at GVA=GPA with 2MiB block page tables.
 *   - Syscall handlers that translate Linux syscalls to macOS equivalents.
 *
 * Usage: elfuse [--verbose] [--timeout N] [--sysroot PATH] <elf-path> [args...]
 */

#include <Hypervisor/Hypervisor.h>
#include <Hypervisor/hv_vcpu.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "utils.h"

#include "core/bootstrap.h"
#include "core/guest.h"
#include "core/launch.h"
#include "core/rosetta.h"
#include "core/sysroot.h"

#include "runtime/forkipc.h"
#include "runtime/proctitle.h"

#include "syscall/fuse.h"
#include "syscall/path.h"
#include "syscall/proc.h"

#include "debug/log.h"
#include "debug/syscall-hist.h"

static int parse_int_arg(const char *s, int min, int max, int *out)
{
    /* Seed end with s (strtol's no-conversion result) so the end == s guard
     * below catches a failed parse without a separate NULL check.
     */
    char *end = (char *) s;
    errno = 0;
    long value = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || value < min || value > max)
        return -1;
    *out = (int) value;
    return 0;
}

static int resolve_guest_elf_host_path(const char *elf_guest_path,
                                       char *elf_host_path,
                                       size_t elf_host_path_sz,
                                       bool *elf_host_temp)
{
    path_translation_t tx;
    if (!elf_guest_path || !elf_host_path || elf_host_path_sz == 0 ||
        !elf_host_temp) {
        errno = EINVAL;
        return -1;
    }

    *elf_host_temp = false;
    if (path_translate_at(LINUX_AT_FDCWD, elf_guest_path, PATH_TR_NONE, &tx) <
        0)
        return -1;

    if (tx.fuse_path) {
        int rc = fuse_materialize_path(tx.intercept_path, elf_host_path,
                                       elf_host_path_sz);
        if (rc < 0) {
            errno = -rc;
            return -1;
        }
        *elf_host_temp = true;
        return 0;
    }

    size_t len = str_copy_trunc(elf_host_path, tx.host_path, elf_host_path_sz);
    if (len >= elf_host_path_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static void free_guest_argv(const char **guest_argv, int guest_argc)
{
    if (!guest_argv)
        return;
    for (int i = 0; i < guest_argc; i++)
        free((void *) guest_argv[i]);
    free((void *) guest_argv);
}

/* Free a guest envp vector produced by build_guest_env. Each entry is a
 * heap "KEY=VAL" string owned by us (never a borrowed environ pointer), so
 * free every slot then the array. A NULL envp (meaning "use host environ")
 * is a no-op.
 */
static void free_envp(char **envp)
{
    if (!envp)
        return;
    for (char **e = envp; *e; e++)
        free(*e);
    free((void *) envp);
}

/* Free the raw --env override array collected during option parsing. These
 * strings are distinct from build_guest_env's output (which strdups its own
 * copies), so both must be freed.
 */
static void free_env_overrides(char **env_overrides, int n)
{
    free_guest_argv((const char **) env_overrides, n);
}

/* Build the guest environment vector, mirroring `env(1)` semantics. Returns 0
 * and sets *out_envp to either:
 *   - NULL when no --env/--clear-env was given, meaning "use the host environ
 *     as-is" (the pre-flag behavior, preserved exactly), or
 *   - a malloc'd, NULL-terminated char** of strdup'd "KEY=VAL" strings (caller
 *     frees with free_envp): the base is the host environ, or empty under
 *     clear_env, and each override replaces a matching KEY= in place or
 * appends. "KEY=VAL" sets; a bare "KEY" inherits KEY from the host environ,
 * skipped when unset so it can never create an empty-string variable. Returns
 * -1 on allocation failure (out_envp untouched).
 */
static int build_guest_env(char *const *overrides,
                           int n_overrides,
                           bool clear_env,
                           char ***out_envp)
{
    if (n_overrides == 0 && !clear_env) {
        *out_envp = NULL;
        return 0;
    }

    extern char **environ;
    int cap = 1; /* NULL terminator */
    if (!clear_env)
        for (char **e = environ; *e; e++)
            cap++;
    cap += n_overrides;

    char **envp = (char **) calloc((size_t) cap, sizeof(char *));
    if (!envp)
        return -1;
    int n = 0;

    if (!clear_env) {
        for (char **e = environ; *e; e++) {
            envp[n] = strdup(*e);
            if (!envp[n])
                goto fail;
            n++;
        }
    }

    for (int i = 0; i < n_overrides; i++) {
        const char *ov = overrides[i];
        const char *eq = strchr(ov, '=');
        /* Reject an empty variable name ("--env =VAL", or a bare "--env ""):
         * eq == ov (or an empty ov) means a zero-length key. setenv(3), whose
         * semantics --env mirrors, rejects an empty name, and appending
         * "=VAL" verbatim would hand the guest a malformed environ entry the
         * dedup scan cannot match. */
        if ((size_t) (eq ? eq - ov : strlen(ov)) == 0) {
            log_error("invalid --env entry \"%s\": empty variable name", ov);
            goto fail;
        }
        char *entry;
        if (eq) {
            entry = strdup(ov);
        } else {
            const char *val = getenv(ov);
            if (!val)
                continue; /* bare KEY, unset on host: skip */
            size_t need = strlen(ov) + 1 + strlen(val) + 1;
            entry = (char *) malloc(need);
            if (entry)
                snprintf(entry, need, "%s=%s", ov, val);
        }
        if (!entry)
            goto fail;

        size_t klen = (size_t) (eq ? eq - ov : strlen(ov));
        int found = -1;
        for (int j = 0; j < n; j++) {
            if (envp[j] && strncmp(envp[j], ov, klen) == 0 &&
                envp[j][klen] == '=') {
                found = j;
                break;
            }
        }
        if (found >= 0) {
            free(envp[found]);
            envp[found] = entry;
        } else {
            /* cap is an exact upper bound (host environ + n_overrides + the
             * NULL slot) and each override appends at most once, so the
             * append can never outgrow the allocation.
             */
            envp[n++] = entry;
        }
    }
    envp[n] = NULL;
    *out_envp = envp;
    return 0;

fail:
    free_envp(envp);
    return -1;
}

static void cleanup_main_resources(guest_t *g,
                                   bool guest_initialized,
                                   sysroot_mount_t *sysroot_mount,
                                   const char *host_cwd,
                                   const char **guest_argv,
                                   int guest_argc,
                                   char *elf_path,
                                   char *sysroot_path)
{
    if (guest_initialized)
        guest_destroy(g);
    rosettad_clear_binary_path();
    if (host_cwd && host_cwd[0] != '\0' && chdir(host_cwd) < 0)
        (void) chdir("/");
    sysroot_cleanup_mount(sysroot_mount);
    free_guest_argv(guest_argv, guest_argc);
    free((void *) elf_path);
    free((void *) sysroot_path);
}

/* The infra-reserve layout invariants documented in guest.h are derived from
 * raw offset constants, so a future edit that grows the pool by shifting one
 * offset without the others would silently overlap two regions. Enforce them at
 * build time rather than trusting the comment.
 */
_Static_assert(INFRA_PT_POOL_END_OFF == INFRA_SHIM_OFF,
               "PT pool must end exactly where the shim slot begins");
_Static_assert(INFRA_SHIM_DATA_OFF + BLOCK_2MIB == INFRA_RESERVE,
               "shim_data must occupy the top 2MiB block of the reserve");
_Static_assert((INFRA_SHIM_DATA_OFF & (BLOCK_2MIB - 1)) == 0,
               "shim_data must be 2MiB-aligned");
_Static_assert((INFRA_PT_POOL_OFF & 0xFFF) == 0 &&
                   (INFRA_PT_POOL_END_OFF & 0xFFF) == 0,
               "PT pool offsets must be page-aligned");

/* Build-time version string (generated by make into build/version.h) */
#include "version.h"

/* Host descriptors used outside the guest FD table. Blocking I/O may hold two
 * duplicated descriptors per guest thread (for example, copy_file_range()),
 * requiring up to 2 * MAX_THREADS descriptors. Keep another 128 descriptors
 * for runtime pipes, fork IPC, debugger sockets, sysroot/FUSE plumbing, and
 * similar bounded overhead. Operations whose descriptor use grows with their
 * input set, such as ppoll(), require separate accounting.
 */
#define HOST_FD_RESERVE 256

static int host_nofile_ensure_capacity(void)
{
    const rlim_t required = (rlim_t) FD_TABLE_SIZE + HOST_FD_RESERVE;
    struct rlimit limit;

    if (getrlimit(RLIMIT_NOFILE, &limit) < 0) {
        log_error("failed to read host RLIMIT_NOFILE: %s", strerror(errno));
        return -1;
    }
    if (limit.rlim_cur >= required)
        return 0;

    if (limit.rlim_max != RLIM_INFINITY && limit.rlim_max < required) {
        log_error(
            "host RLIMIT_NOFILE hard limit %llu is below the required %llu "
            "(%d guest FDs + %d elfuse reserve)",
            (unsigned long long) limit.rlim_max, (unsigned long long) required,
            FD_TABLE_SIZE, HOST_FD_RESERVE);
        return -1;
    }

    rlim_t old_soft = limit.rlim_cur;
    limit.rlim_cur = required;
    if (setrlimit(RLIMIT_NOFILE, &limit) < 0) {
        log_error("failed to raise host RLIMIT_NOFILE from %llu to %llu: %s",
                  (unsigned long long) old_soft, (unsigned long long) required,
                  strerror(errno));
        return -1;
    }

    return 0;
}

/* Verify the host CPU's DC ZVA granule matches the shim's hardcoded value.
 *
 * DCZID_EL0 is readable from EL0 without trapping, so guest libc reads the
 * host's value directly and uses it as the stride for memset(0) loops. The shim
 * emulates each trapped DC ZVA by zeroing exactly 64 bytes (src/core/shim.S).
 * Apple Silicon M1..M4 report DCZID_EL0.BS=4 (64 bytes); any future host that
 * advertises a different granule would cause silent partial-zero corruption of
 * guest memory. Abort here so the mismatch surfaces at startup instead of as
 * data corruption later.
 */
static int host_dc_zva_assert(void)
{
    uint64_t dczid;
    __asm__ volatile("mrs %0, DCZID_EL0" : "=r"(dczid));
    if (dczid & (1ULL << 4)) {
        log_error(
            "host CPU prohibits DC ZVA (DCZID_EL0.DZP=1); cannot run "
            "guests that depend on it");
        return -1;
    }
    unsigned bs = (unsigned) (dczid & 0xF);
    if (bs != 4) {
        log_error(
            "host DCZID_EL0.BS=%u (%u-byte DC ZVA block) but the shim "
            "emulates 64 bytes; update src/core/shim.S before running",
            bs, 1u << (bs + 2));
        return -1;
    }
    return 0;
}

/* One-line usage synopsis shared by the argument-error paths; --help prints
 * the long multi-line form. A single definition keeps the copies from
 * drifting (one copy had already lost the --gdb flags).
 */
#define ELFUSE_USAGE                                           \
    "usage: elfuse [--verbose] [--timeout N] "                 \
    "[--sysroot PATH] [--create-sysroot PATH] [--no-rosetta] " \
    "[--fakeroot] [--gdb PORT] [--gdb-stop-on-entry] "         \
    "[--user UID[:GID]] [--workdir DIR] [--env KEY=VAL] "      \
    "[--clear-env] <elf-path> [args...]"

int main(int argc, char **argv)
{
    log_init();
    /* Resolve ELFUSE_STARTUP_TRACE before any guest syscall can fire so the
     * histogram captures the very first dynamic-linker openat.
     */
    syscall_hist_init();

    bool verbose = false;
    /* x86_64-via-Rosetta is on by default; --no-rosetta or ELFUSE_NO_ROSETTA=1
     * disables it. Architecture is auto-detected from the ELF header in
     * guest_bootstrap_prepare; the access() probe in rosetta_prepare surfaces
     * an install hint if Rosetta is not present.
     */
    bool rosetta_enabled = true;
    int timeout_sec = 10, fork_child_fd = -1, vfork_notify_fd = -1;
    const char *sysroot = NULL;
    const char *create_sysroot = NULL;
    int gdb_port = 0;
    bool gdb_stop_on_entry = false;
    bool fakeroot = false;
    /* Launch flags driven by `elfuse-oci run` (and usable directly). They
     * map onto launch_args_t fields; --user overrides the guest identity,
     * --workdir sets the guest's initial cwd, --env/--clear-env build the
     * guest environment. All are additive: existing flags are unchanged.
     */
    bool has_creds = false;
    uint32_t uid = 0, gid = 0;
    char *workdir = NULL;
    char **env_overrides = NULL;
    int n_env_overrides = 0, env_cap = 0;
    bool clear_env = false;
    int arg_start = 1;

    /* 'elfuse rosettad translate <in> <out>' runs the real Apple rosettad
     * binary inside an elfuse guest to materialise an AOT translation. The
     * rosettad bridge in src/core/rosetta.c invokes this on cache miss; the
     * subcommand rewrites argv so the rest of main proceeds as a normal
     * aarch64-linux execution of rosettad with the requested arguments.
     */
    if (argc >= 5 && !strcmp(argv[1], "rosettad") &&
        !strcmp(argv[2], "translate")) {
        static char *rewritten[6];
        rewritten[0] = argv[0];
        rewritten[1] = (char *) ROSETTAD_TRANSLATOR_PATH;
        rewritten[2] = (char *) "translate";
        rewritten[3] = argv[3];
        rewritten[4] = argv[4];
        rewritten[5] = NULL;
        argv = rewritten;
        argc = 5;
    }

    /* --help and --version do not require an ELF path. */
    if (argc > 1) {
        if (!strcmp(argv[1], "--version") || !strcmp(argv[1], "-V")) {
            printf("elfuse %s\n", ELFUSE_VERSION);
            return 0;
        }
        if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
            printf(
                "usage: elfuse [--verbose] [--timeout N] [--sysroot PATH]\n"
                "              [--create-sysroot PATH]\n"
                "              [--no-rosetta] [--fakeroot]\n"
                "              [--gdb PORT] [--gdb-stop-on-entry]\n"
                "              [--user UID[:GID]] [--workdir DIR]\n"
                "              [--env KEY=VAL] [--clear-env]\n"
                "              <elf-path> [args...]\n"
                "\n"
                "Options:\n"
                "  -h, --help              Show this help and exit\n"
                "  -V, --version           Show version and exit\n"
                "  -v, --verbose           Trace each guest syscall\n"
                "  --timeout N             Per-iteration vCPU run timeout "
                "(seconds, default 10; 0 disables)\n"
                "  --sysroot PATH          Resolve absolute guest paths under "
                "PATH first\n"
                "  --create-sysroot PATH   Provision and use a case-sensitive "
                "APFS sparsebundle mounted at PATH\n"
                "  --no-rosetta            Disable x86_64-via-Rosetta "
                "(architecture is auto-detected from the ELF header; "
                "on by default)\n"
                "  --fakeroot              Enable fakeroot mode (sets guest "
                "UID/GID to 0 and provides full caps)\n"
                "  --gdb PORT              Listen for GDB Remote Serial "
                "Protocol on PORT\n"
                "  --gdb-stop-on-entry     Halt before the first guest "
                "instruction\n"
                "  --user UID[:GID]        Run the guest as UID (and GID; "
                "defaults to UID). Numeric; elfuse-oci resolves symbolic "
                "names\n"
                "  --workdir DIR           Guest-absolute initial working "
                "directory (resolved under --sysroot)\n"
                "  --env KEY=VAL           Set a guest environment variable; "
                "repeatable. 'KEY' (no '=') inherits from the host environ\n"
                "  --clear-env             Start the guest environment empty "
                "(only --env entries apply); default inherits the host "
                "environ\n");
            return 0;
        }
    }

    if (host_dc_zva_assert() < 0)
        return 1;

    /* Parse elfuse options until the first guest argv element. */
    while (arg_start < argc && argv[arg_start][0] == '-') {
        if (!strcmp(argv[arg_start], "--verbose") ||
            !strcmp(argv[arg_start], "-v")) {
            verbose = true;
            log_set_level(LOG_DEBUG);
            arg_start++;
        } else if ((!strcmp(argv[arg_start], "--timeout") ||
                    !strcmp(argv[arg_start], "-t")) &&
                   arg_start + 1 < argc) {
            if (parse_int_arg(argv[arg_start + 1], 0, INT_MAX, &timeout_sec) <
                0)
                timeout_sec = 10;
            arg_start += 2;
        } else if (!strcmp(argv[arg_start], "--fork-child") &&
                   arg_start + 1 < argc) {
            if (parse_int_arg(argv[arg_start + 1], 0, INT_MAX, &fork_child_fd) <
                0) {
                log_error("invalid fork child fd: %s", argv[arg_start + 1]);
                return 1;
            }
            arg_start += 2;
        } else if (!strcmp(argv[arg_start], "--vfork-notify-fd") &&
                   arg_start + 1 < argc) {
            if (parse_int_arg(argv[arg_start + 1], 0, INT_MAX,
                              &vfork_notify_fd) < 0) {
                log_error("invalid vfork notify fd: %s", argv[arg_start + 1]);
                return 1;
            }
            arg_start += 2;
        } else if (!strcmp(argv[arg_start], "--sysroot") &&
                   arg_start + 1 < argc) {
            sysroot = argv[arg_start + 1];
            arg_start += 2;
        } else if (!strcmp(argv[arg_start], "--create-sysroot") &&
                   arg_start + 1 < argc) {
            create_sysroot = argv[arg_start + 1];
            arg_start += 2;
        } else if (!strcmp(argv[arg_start], "--no-rosetta")) {
            rosetta_enabled = false;
            arg_start++;
        } else if (!strcmp(argv[arg_start], "--fakeroot")) {
            fakeroot = true;
            arg_start++;
        } else if (!strcmp(argv[arg_start], "--gdb") && arg_start + 1 < argc) {
            if (parse_int_arg(argv[arg_start + 1], 1, 65535, &gdb_port) < 0) {
                log_error("invalid GDB port: %s", argv[arg_start + 1]);
                return 1;
            }
            if (!verbose)
                log_set_level(LOG_INFO);
            arg_start += 2;
        } else if (!strcmp(argv[arg_start], "--gdb-stop-on-entry")) {
            gdb_stop_on_entry = true;
            arg_start++;
        } else if (!strcmp(argv[arg_start], "--user") && arg_start + 1 < argc) {
            /* Numeric UID[:GID]; elfuse-oci resolves symbolic User
             * against the image /etc/passwd+group and passes numbers. A bare
             * UID sets gid=uid (typical single-user image).
             */
            const char *spec = argv[arg_start + 1];
            char *end;
            errno = 0;
            unsigned long u = strtoul(spec, &end, 10);
            if (errno || end == spec || u > UINT32_MAX) {
                log_error("invalid --user UID: %s", spec);
                goto fail_parse;
            }
            unsigned long gg = u;
            if (*end == ':') {
                errno = 0;
                char *end2;
                gg = strtoul(end + 1, &end2, 10);
                if (errno || end2 == end + 1 || *end2 != '\0' ||
                    gg > UINT32_MAX) {
                    log_error("invalid --user UID:GID: %s", spec);
                    goto fail_parse;
                }
            } else if (*end != '\0') {
                log_error("invalid --user spec: %s", spec);
                goto fail_parse;
            }
            uid = (uint32_t) u;
            gid = (uint32_t) gg;
            has_creds = true;
            arg_start += 2;
        } else if (!strcmp(argv[arg_start], "--workdir") &&
                   arg_start + 1 < argc) {
            /* Guest-absolute working directory; elfuse_launch translates it
             * against the sysroot and chdirs there. Reject relative paths up
             * front: translation would resolve them against the host cwd,
             * silently starting the guest outside the intended tree. strdup
             * now because runtime_set_process_title clobbers the original
             * argv block.
             */
            if (argv[arg_start + 1][0] != '/') {
                log_error("--workdir requires a guest-absolute path, got %s",
                          argv[arg_start + 1]);
                goto fail_parse;
            }
            free(workdir);
            workdir = strdup(argv[arg_start + 1]);
            if (!workdir) {
                log_error("out of memory");
                goto fail_parse;
            }
            arg_start += 2;
        } else if (!strcmp(argv[arg_start], "--env") && arg_start + 1 < argc) {
            /* "KEY=VAL" sets; "KEY" inherits from the host environ (resolved
             * in build_guest_env). strdup now; argv is clobbered later.
             */
            if (n_env_overrides == env_cap) {
                int ncap = env_cap ? env_cap * 2 : 8;
                char **grown = (char **) realloc(
                    (void *) env_overrides, (size_t) ncap * sizeof(char *));
                if (!grown) {
                    log_error("out of memory");
                    goto fail_parse;
                }
                env_overrides = grown;
                env_cap = ncap;
            }
            env_overrides[n_env_overrides] = strdup(argv[arg_start + 1]);
            if (!env_overrides[n_env_overrides]) {
                log_error("out of memory");
                goto fail_parse;
            }
            n_env_overrides++;
            arg_start += 2;
        } else if (!strcmp(argv[arg_start], "--clear-env")) {
            clear_env = true;
            arg_start++;
        } else if (!strcmp(argv[arg_start], "--")) {
            arg_start++;
            break;
        } else {
            log_error("unknown option: %s", argv[arg_start]);
            log_error(ELFUSE_USAGE);
            goto fail_parse;
        }
    }

    if (sysroot && create_sysroot) {
        log_error(
            "use either --sysroot PATH or --create-sysroot PATH, not both");
        goto fail_parse;
    }

    /* ELFUSE_NO_ROSETTA=1 mirrors --no-rosetta for environments where passing
     * flags is awkward (test harnesses, wrapper scripts). Unset or any other
     * value leaves the default on. Commit the result before the --fork-child
     * early-return so helper processes inherit the parent's opt-out semantics
     * exactly.
     */
    if (rosetta_enabled) {
        const char *no_rosetta_env = getenv("ELFUSE_NO_ROSETTA");
        if (no_rosetta_env && strcmp(no_rosetta_env, "1") == 0)
            rosetta_enabled = false;
    }
    proc_set_rosetta_enabled(rosetta_enabled);

    if (!fakeroot) {
        const char *fakeroot_env = getenv("ELFUSE_FAKEROOT");
        if (fakeroot_env && strcmp(fakeroot_env, "1") == 0)
            fakeroot = true;
    }
    proc_set_fakeroot_enabled(fakeroot);

    /* Top-level processes establish the capacity; fork helpers normally
     * inherit it, but recheck before receiving the parent's FD table. Guest
     * RLIMIT_NOFILE state is virtualized separately and cannot lower this
     * internal host reserve.
     */
    if (host_nofile_ensure_capacity() < 0)
        goto fail_parse;

    /* Block the vCPU-preemption signals and start the sigwait thread before any
     * vCPU thread exists, so both the normal path and the fork-child path below
     * inherit the block on every thread they spawn.
     */
    if (proc_preempt_init() < 0)
        goto fail_parse;

    /* Fork-child mode: receive VM state over IPC and run */
    if (fork_child_fd >= 0)
        return fork_child_main(fork_child_fd, vfork_notify_fd, verbose,
                               timeout_sec);

    if (arg_start >= argc) {
        log_error(ELFUSE_USAGE);
        goto fail_parse;
    }

    /* Shared unwind for argument-parsing errors past the point where --env /
     * --workdir may have allocated: frees those two (the only heap state owned
     * before the elf_path/guest_argv copies below) and exits 1. Placed before
     * those later declarations so no goto crosses into their scope; post-copy
     * paths use the cleanup: label instead.
     */
    if (0) {
    fail_parse:
        free_env_overrides(env_overrides, n_env_overrides);
        free(workdir);
        return 1;
    }

    /* Copy elf_path and guest_argv to heap because the original argv string
     * data lives in a contiguous stack region that elfuse clobbers below for
     * the process title (PostgreSQL/nginx argv-clobber technique).
     */
    char *elf_path = strdup(argv[arg_start]);
    bool have_sysroot = (sysroot != NULL || create_sysroot != NULL);
    const char *sysroot_src = create_sysroot ? create_sysroot : sysroot;
    char *sysroot_path = NULL;
    if (have_sysroot) {
        sysroot_path = (char *) calloc(LINUX_PATH_MAX, 1);
        if (sysroot_path) {
            size_t src_len =
                str_copy_trunc(sysroot_path, sysroot_src, LINUX_PATH_MAX);
            if (src_len >= LINUX_PATH_MAX) {
                log_error("sysroot path too long (%zu bytes, max %d): %s",
                          src_len, LINUX_PATH_MAX - 1, sysroot_src);
                free(elf_path);
                free(sysroot_path);
                free_env_overrides(env_overrides, n_env_overrides);
                free(workdir);
                return 1;
            }
        }
    }
    sysroot = sysroot_path;
    int guest_argc = argc - arg_start;
    const char **guest_argv =
        (const char **) calloc((size_t) guest_argc, sizeof(char *));
    guest_t g;
    bool guest_initialized = false;
    sysroot_mount_t sysroot_mount;
    char host_cwd[LINUX_PATH_MAX];
    char elf_host_path[LINUX_PATH_MAX];
    bool elf_host_temp = false;
    bool have_host_cwd = (getcwd(host_cwd, sizeof(host_cwd)) != NULL);
    /* Declared (and NULL-initialized) before the first `goto fail` so the
     * shared cleanup below never frees an uninitialized pointer.
     */
    char **envp = NULL;
    int exit_code;
    memset(&sysroot_mount, 0, sizeof(sysroot_mount));
    if (!elf_path || (have_sysroot && !sysroot_path) || !guest_argv) {
        log_error("out of memory");
        goto fail;
    }
    for (int i = 0; i < guest_argc; i++) {
        guest_argv[i] = strdup(argv[arg_start + i]);
        if (!guest_argv[i]) {
            log_error("out of memory");
            goto fail;
        }
    }

    if (create_sysroot) {
        if (sysroot_create_mount(sysroot_path, &sysroot_mount) < 0) {
            log_error("failed to provision case-sensitive sysroot at %s: %s",
                      sysroot_path, strerror(errno));
            goto fail;
        }
        size_t mounted_len = str_copy_trunc(
            sysroot_path, sysroot_mount.mount_path, LINUX_PATH_MAX);
        if (mounted_len >= LINUX_PATH_MAX) {
            log_error("mounted sysroot path too long: %s",
                      sysroot_mount.mount_path);
            goto fail;
        }
        sysroot = sysroot_path;
    }

    if (have_sysroot && sysroot_validate_case_sensitivity(sysroot) < 0)
        goto fail;

    proc_set_sysroot(sysroot);

    int shebang_depth = 0;

    while (true) {
        if (resolve_guest_elf_host_path(elf_path, elf_host_path,
                                        sizeof(elf_host_path),
                                        &elf_host_temp) < 0) {
            log_error("failed to resolve ELF path %s: %s", elf_path,
                      strerror(errno));
            goto fail;
        }

        /* Check if the file starts with "#!" */
        char interp[LINUX_PATH_MAX];
        char arg[LINUX_PATH_MAX];
        int rc = elf_read_shebang(elf_host_path, interp, sizeof(interp), arg,
                                  sizeof(arg));
        if (rc == 0) {
            /* Not a shebang script, proceed to boot */
            break;
        }

        if (rc < 0) {
            log_error("empty or invalid shebang interpreter in %s", elf_path);
            goto fail;
        }

        /* The current path is a script. Bound the resolution chain only once a
         * further shebang is confirmed, so a max-depth chain ending in a real
         * ELF still boots (matches sys_execve and the Linux kernel).
         */
        if (shebang_depth >= ELF_SHEBANG_MAX_DEPTH) {
            log_error(
                "too many levels of shebang recursion (max %d) "
                "resolving %s",
                ELF_SHEBANG_MAX_DEPTH, argv[arg_start]);
            goto fail;
        }
        shebang_depth++;

        /* Prepend interpreter (and argument if present) to guest_argv */
        bool has_arg = (arg[0] != '\0');
        int add_count = has_arg ? 2 : 1;
        int new_argc = guest_argc + add_count;
        const char **new_argv =
            (const char **) calloc((size_t) new_argc, sizeof(char *));
        if (!new_argv) {
            log_error("out of memory");
            goto fail;
        }

        new_argv[0] = strdup(interp);
        if (!new_argv[0]) {
            log_error("out of memory");
            free((void *) new_argv);
            goto fail;
        }
        if (has_arg) {
            new_argv[1] = strdup(arg);
            if (!new_argv[1]) {
                log_error("out of memory");
                free((void *) new_argv[0]);
                free((void *) new_argv);
                goto fail;
            }
        }

        /* Transfer ownership of the previous guest_argv elements */
        for (int i = 0; i < guest_argc; i++) {
            new_argv[i + add_count] = guest_argv[i];
        }

        free((void *) guest_argv);
        guest_argv = new_argv;
        guest_argc = new_argc;

        /* Update elf_path to point to the interpreter path */
        char *new_elf_path = strdup(interp);
        if (!new_elf_path) {
            log_error("out of memory");
            goto fail;
        }
        free(elf_path);
        elf_path = new_elf_path;

        /* Clean up any materialized temp file before resolving the next path */
        if (elf_host_temp) {
            unlink(elf_host_path);
            elf_host_temp = false;
        }
    }

    if (gdb_port > 0) {
        elf_info_t probe_info;
        if (guest_bootstrap_probe_elf(elf_host_path, &probe_info) == 0 &&
            probe_info.e_machine == EM_X86_64) {
            log_error(
                "--gdb is not supported for x86_64 guests; the current stub "
                "only exposes the translated aarch64 view");
            goto fail;
        }
    }

    /* Build the guest environment vector late (after the shebang loop and the
     * --gdb guard) so only this block's OOM path and the post-launch cleanup
     * must free it. With neither --env nor --clear-env given, build_guest_env
     * leaves envp NULL and elfuse_launch uses the host environ (pre-flag
     * behavior, preserved); it owns that condition, not this call site.
     */
    if (build_guest_env(env_overrides, n_env_overrides, clear_env, &envp) < 0) {
        /* build_guest_env has already logged the specific reason (OOM or a
         * malformed --env entry).
         */
        goto fail;
    }
    /* build_guest_env strdups its own copies, so the raw override array and
     * its strings are no longer needed.
     */
    free_env_overrides(env_overrides, n_env_overrides);
    env_overrides = NULL;
    n_env_overrides = 0;

    /* Rewrite the host-visible process title from the guest entrypoint. This
     * clobbers the original argv block (already snapshotted into the heap
     * elf_path / guest_argv above), so it must run before elfuse_launch hands
     * control to the guest but after the shebang loop has fixed elf_path.
     */
    runtime_set_process_title(argc, argv, elf_path);

    /* Hand bring-up, run loop, and guest teardown to elfuse_launch. main()
     * keeps ownership of the original argv (proctitle above), the sysroot mount
     * (detached in cleanup_main_resources after the guest exits so it stays
     * live for the whole run), host cwd, and the heap elf_path / sysroot_path /
     * guest_argv / envp / workdir copies.
     */
    launch_args_t largs = {
        .elf_path = elf_host_path,
        .elf_host_temp = elf_host_temp,
        .sysroot = sysroot,
        .guest_argc = guest_argc,
        .guest_argv = guest_argv,
        .envp = envp,
        .has_creds = has_creds,
        .uid = uid,
        .gid = gid,
        .cwd_guest = workdir,
        .gdb_port = gdb_port,
        .gdb_stop_on_entry = gdb_stop_on_entry,
        .timeout_sec = timeout_sec,
        .verbose = verbose,
    };
    /* elfuse_launch owns the temp unlink from the prepare call onward, so
     * drop main()'s claim before handing off: the shared cleanup below must
     * not unlink a path whose ownership has been transferred.
     */
    elf_host_temp = false;
    exit_code = elfuse_launch(&largs);
    goto cleanup;

fail:
    exit_code = 1;
cleanup:
    /* Single unwind for every exit past the heap-copy allocations. On the
     * success path elfuse_launch has already run guest_destroy
     * (guest_initialized never becomes true in main), so this frees the
     * caller-owned heap copies, detaches the sysroot mount, restores the host
     * cwd, and drops a still-owned FUSE-materialized temp ELF. A successful
     * build_guest_env already freed and reset the override array, so freeing it
     * here is then a no-op.
     */
    free_env_overrides(env_overrides, n_env_overrides);
    free_envp(envp);
    free(workdir);
    cleanup_main_resources(&g, guest_initialized, &sysroot_mount,
                           have_host_cwd ? host_cwd : NULL, guest_argv,
                           guest_argc, elf_path, sysroot_path);
    if (elf_host_temp)
        unlink(elf_host_path);

    return exit_code;
}
