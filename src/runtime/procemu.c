/* /proc and /dev path emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Intercepts openat and readlinkat for /proc, /dev, /etc, and /var/run paths.
 * Returns host fds for synthetic content, or -2 if the path is not intercepted
 * (caller falls through to real syscall).
 */

/* Maximum /proc/self/maps entries. Array is sized to this; loop bounds use
 * MAPS_ENTRY_MAX - 1 to leave room for safe increment.
 */
#define MAPS_ENTRY_MAX 256

/* Column at which the region name starts in /proc/self/maps output.
 * Matches observed Linux kernel formatting (verified via strace).
 */
#define MAPS_NAME_COLUMN 73

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <libproc.h>
#include <mach/mach.h>

#include "utils.h"

#include "debug/log.h"
#include "runtime/procemu.h"
#include "runtime/thread.h"

#include "syscall/abi.h"
#include "syscall/internal.h"
#include "syscall/proc.h"
#include "syscall/sys.h"

/* Return the shared /dev/shm emulation directory, creating it on first call.
 * Linux POSIX shm names live in one namespace, so this must not be keyed by
 * the host process id.
 *
 * Uses a mutex for thread-safe lazy initialization while still allowing
 * retries after transient failures. The mkdir+lstat sequence has an inherent
 * TOCTOU window, but the lstat ownership check limits the impact to directories
 * already owned by this UID.
 */
static char shm_dir[128];
static bool shm_dir_ok;
static int shm_dir_errno;
static pthread_mutex_t shm_dir_lock = PTHREAD_MUTEX_INITIALIZER;

/* Synthetic /proc directory backing store. Lazily initialized by
 * ensure_proc_tmpdir() on first access to any /proc path that needs directory
 * enumeration (find, ls, etc.). Protected by proc_tmpdir_lock for thread safety
 * (multiple vCPUs can reach proc_intercept_open concurrently without holding a
 * global lock).
 */
static char proc_tmpdir[128];
static bool proc_tmpdir_ok;
static pthread_mutex_t proc_tmpdir_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic int oom_score_adj_value = 0;

/* atexit cleanup: remove snapshot files and the temp directory tree. */
static void proc_tmpdir_cleanup(void)
{
    if (!proc_tmpdir_ok || proc_tmpdir[0] == '\0')
        return;

    /* Remove known files inside <tmpdir>/<pid>/ and <tmpdir>/ */
    char path[256];
    const char *files[] = {"stat", "status", "cmdline", "maps", "exe", NULL};
    char piddir[160];

    /* Reconstruct pid subdir by scanning for the first numeric entry */
    DIR *d = opendir(proc_tmpdir);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d))) {
            if (ent->d_name[0] < '1' || ent->d_name[0] > '9')
                continue;
            snprintf(piddir, sizeof(piddir), "%s/%s", proc_tmpdir, ent->d_name);
            for (const char **f = files; *f; f++) {
                snprintf(path, sizeof(path), "%s/%s", piddir, *f);
                unlink(path);
            }
            /* Remove task subdirectory (may contain TID subdirs) */
            snprintf(path, sizeof(path), "%s/task", piddir);
            rmdir(path);
            rmdir(piddir);
        }
        closedir(d);
    }
    snprintf(path, sizeof(path), "%s/self", proc_tmpdir);
    unlink(path); /* symlink */
    rmdir(proc_tmpdir);
}

static void shm_dir_init(void)
{
    shm_dir_errno = EACCES;
    snprintf(shm_dir, sizeof(shm_dir), "/tmp/elfuse-shm-%u",
             (unsigned) getuid());
    if (mkdir(shm_dir, 0700) < 0 && errno != EEXIST) {
        shm_dir_errno = errno;
        shm_dir[0] = '\0';
        return;
    }
    /* Verify the path is a directory owned by the current UID (not a symlink).
     */
    struct stat st;
    if (lstat(shm_dir, &st) < 0) {
        shm_dir_errno = errno;
        log_error("/dev/shm dir %s: lstat failed: %s", shm_dir,
                  strerror(errno));
        shm_dir[0] = '\0';
        return;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid()) {
        shm_dir_errno = EACCES;
        log_error(
            "/dev/shm dir %s is not a directory owned by "
            "uid %u",
            shm_dir, (unsigned) getuid());
        shm_dir[0] = '\0';
        return;
    }
    shm_dir_ok = true;
}

static const char *shm_dir_path(void)
{
    pthread_mutex_lock(&shm_dir_lock);
    if (!shm_dir_ok)
        shm_dir_init();

    int saved_errno = shm_dir_ok ? 0 : (shm_dir_errno ? shm_dir_errno : EACCES);
    const char *result = shm_dir_ok ? shm_dir : NULL;
    pthread_mutex_unlock(&shm_dir_lock);

    if (!result)
        errno = saved_errno;
    return result;
}

const char *proc_get_shm_dir(void)
{
    return shm_dir_path();
}

/* Create a synthetic file from a buffer. Returns a host fd positioned at the
 * start, or -1 on failure. Caller owns the returned fd.
 * Uses a temp file (unlinked immediately) so that pread/lseek work.
 */
static int proc_synthetic_fd(const void *data, size_t len)
{
    char template[] = "/tmp/elfuse-proc-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0)
        return -1;
    unlink(template); /* Delete on close; fd keeps it alive */

    const uint8_t *p = data;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        p += n;
        remaining -= n;
    }
    lseek(fd, 0, SEEK_SET); /* Rewind so first read starts at beginning */
    return fd;
}

/* Lazy mkdtemp into a caller-provided buffer. Returns 0 on success (buf
 * holds the path), or -1 on failure (buf[0] reset to '\0').
 *
 * Caller must hold the lock that protects buf, since the helper runs the
 * "is buf empty?" check and mkdtemp non-atomically. The created directory
 * is reused across calls until process exit.
 */
static int proc_lazy_mkdtemp(char *buf, size_t buf_size, const char *template)
{
    if (buf[0])
        return 0;
    str_copy_trunc(buf, template, buf_size);
    if (!mkdtemp(buf)) {
        buf[0] = '\0';
        return -1;
    }
    return 0;
}

/* Wrap an snprintf-style result into a synthetic fd, clamping the length into
 * the inclusive range zero through capacity-1. Common pattern for /proc/self
 * string files.
 */
static int proc_synthetic_fd_str(const char *buf, int snprintf_ret, size_t cap)
{
    if (snprintf_ret < 0)
        snprintf_ret = 0;
    if ((size_t) snprintf_ret >= cap)
        snprintf_ret = (int) (cap - 1);
    return proc_synthetic_fd(buf, (size_t) snprintf_ret);
}

static int append_proc_net_row(char *buf,
                               size_t bufsz,
                               int off,
                               bool want_tcp,
                               int sl,
                               const char laddr[33],
                               uint16_t lport,
                               const char raddr[33],
                               uint16_t rport,
                               int st)
{
    if (want_tcp) {
        return off + snprintf(buf + off, bufsz - (size_t) off,
                              "%4d: %s:%04X %s:%04X %02X "
                              "00000000:00000000 00:00000000 00000000"
                              "  1000        0 %d 1 0000000000000000 "
                              "100 0 0 10 0\n",
                              sl, laddr, lport, raddr, rport, st, 10000 + sl);
    }

    return off + snprintf(buf + off, bufsz - (size_t) off,
                          "%4d: %s:%04X %s:%04X %02X "
                          "00000000:00000000 00:00000000 00000000"
                          "  1000        0 %d 2 0000000000000000 0\n",
                          sl, laddr, lport, raddr, rport, st, 10000 + sl);
}

static int proc_parse_int_write(const void *buf, size_t count, int *out)
{
    const char *src = (const char *) buf;
    size_t len = count;
    char tmp[64];
    char *end;
    long parsed;

    while (len > 0 && (src[len - 1] == '\n' || src[len - 1] == '\r' ||
                       src[len - 1] == ' ' || src[len - 1] == '\t'))
        len--;
    if (len == 0 || len >= sizeof(tmp)) {
        errno = EINVAL;
        return -1;
    }

    memcpy(tmp, buf, len);
    tmp[len] = '\0';
    parsed = strtol(tmp, &end, 10);
    if (end == tmp || *end != '\0' || parsed < INT_MIN || parsed > INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    *out = (int) parsed;
    return 0;
}

static int proc_open_dir_fd(const char *path, int linux_flags)
{
    int oflags = O_RDONLY | O_DIRECTORY;

    if (linux_flags & LINUX_O_CLOEXEC)
        oflags |= O_CLOEXEC;

    return open(path, oflags);
}

static int proc_open_numbered_dir(const char *dir, int64_t id, int linux_flags)
{
    char path[128];
    int n = snprintf(path, sizeof(path), "%s/%lld", dir, (long long) id);

    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return proc_open_dir_fd(path, linux_flags);
}

static int proc_is_oom_writable(const char *path)
{
    return !strcmp(path, "/proc/self/oom_score_adj") ||
           !strcmp(path, "/proc/self/oom_adj");
}

static int proc_is_oom_path(const char *path)
{
    return proc_is_oom_writable(path) || !strcmp(path, "/proc/self/oom_score");
}

static int copy_fd_to_path(int src_fd, const char *path)
{
    int out = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0444);
    if (out < 0)
        return -1;

    if (lseek(src_fd, 0, SEEK_SET) < 0) {
        close(out);
        return -1;
    }

    char buf[4096];
    for (;;) {
        ssize_t n = read(src_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(out);
            return -1;
        }
        if (n == 0)
            break;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t) (n - off));
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                close(out);
                return -1;
            }
            off += w;
        }
    }

    close(out);
    lseek(src_fd, 0, SEEK_SET);
    return 0;
}

static void populate_proc_snapshot(const guest_t *g,
                                   const char *dir,
                                   const char *name,
                                   const char *proc_path)
{
    char path[LINUX_PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int) sizeof(path))
        return;

    int fd = proc_intercept_open(g, proc_path, 0, 0);
    if (fd < 0)
        return;
    copy_fd_to_path(fd, path);
    close(fd);
}

static void format_proc_net_addr(char out[33],
                                 const struct in_sockinfo *ini,
                                 int local,
                                 int v6)
{
    if (!v6) {
        uint32_t addr = local ? ini->insi_laddr.ina_46.i46a_addr4.s_addr
                              : ini->insi_faddr.ina_46.i46a_addr4.s_addr;
        snprintf(out, 33, "%08X", addr);
        return;
    }

    const struct in6_addr *addr =
        local ? &ini->insi_laddr.ina_6 : &ini->insi_faddr.ina_6;
    uint32_t words[4];
    memcpy(words, addr->s6_addr, sizeof(words));
    snprintf(out, 33, "%08X%08X%08X%08X", words[0], words[1], words[2],
             words[3]);
}

/* Lazily create the synthetic /proc directory tree. Returns the path to the
 * temp dir, or NULL on failure. Thread-safe via proc_tmpdir_lock (multiple
 * vCPUs can hit proc_intercept_open concurrently).
 */
static const char *ensure_proc_tmpdir(const guest_t *g)
{
    pthread_mutex_lock(&proc_tmpdir_lock);
    if (proc_tmpdir_ok) {
        pthread_mutex_unlock(&proc_tmpdir_lock);
        return proc_tmpdir;
    }

    str_copy_trunc(proc_tmpdir, "/tmp/elfuse-proc-XXXXXX", sizeof(proc_tmpdir));
    if (!mkdtemp(proc_tmpdir)) {
        proc_tmpdir[0] = '\0';
        pthread_mutex_unlock(&proc_tmpdir_lock);
        return NULL;
    }

    char pidbuf[128], selfbuf[128];
    snprintf(pidbuf, sizeof(pidbuf), "%s/%lld", proc_tmpdir,
             (long long) proc_get_pid());
    if (mkdir(pidbuf, 0755) < 0 && errno != EEXIST) {
        rmdir(proc_tmpdir);
        proc_tmpdir[0] = '\0';
        pthread_mutex_unlock(&proc_tmpdir_lock);
        return NULL;
    }

    char piddir[128];
    str_copy_trunc(piddir, pidbuf, sizeof(piddir));
    populate_proc_snapshot(g, piddir, "stat", "/proc/self/stat");
    populate_proc_snapshot(g, piddir, "status", "/proc/self/status");
    populate_proc_snapshot(g, piddir, "cmdline", "/proc/self/cmdline");
    populate_proc_snapshot(g, piddir, "maps", "/proc/self/maps");

    /* Create task subdirectory for /proc/self/task enumeration */
    char taskdir[128];
    snprintf(taskdir, sizeof(taskdir), "%s/task", piddir);
    mkdir(taskdir, 0755);

    char exepath[128];
    snprintf(exepath, sizeof(exepath), "%s/exe", piddir);
    const char *exe = proc_get_elf_path();
    if (exe)
        symlink(exe, exepath);

    snprintf(selfbuf, sizeof(selfbuf), "%s/self", proc_tmpdir);
    snprintf(pidbuf, sizeof(pidbuf), "%lld", (long long) proc_get_pid());
    symlink(pidbuf, selfbuf); /* best-effort */

    atexit(proc_tmpdir_cleanup);
    proc_tmpdir_ok = true;
    pthread_mutex_unlock(&proc_tmpdir_lock);
    return proc_tmpdir;
}

typedef struct {
    int64_t *tids;
    int ntids;
} proc_task_collect_ctx_t;

static void proc_task_collect_cb(thread_entry_t *t, void *arg)
{
    proc_task_collect_ctx_t *c = arg;
    if (c->ntids < MAX_THREADS)
        c->tids[c->ntids++] = t->guest_tid;
}

static char fddir[128];
static pthread_mutex_t fddir_lock = PTHREAD_MUTEX_INITIALIZER;

static void cleanup_fddir(void)
{
    if (fddir[0] != '\0') {
        for (int i = 0; i < FD_TABLE_SIZE; i++) {
            char entry[192];
            snprintf(entry, sizeof(entry), "%s/%d", fddir, i);
            unlink(entry);
        }
        rmdir(fddir);
    }
}

int proc_intercept_open(const guest_t *g,
                        const char *path,
                        int linux_flags,
                        int mode)
{
    /* /dev/null, /dev/zero, /dev/(u)random, /dev/tty */
    const char *host_dev = NULL;
    int host_accmode = translate_open_flags(linux_flags) & O_ACCMODE;
    if (!strcmp(path, "/dev/null"))
        host_dev = "/dev/null";
    else if (!strcmp(path, "/dev/zero")) {
        host_dev = "/dev/zero";
        /* macOS rejects O_WRONLY on /dev/zero even though Linux permits it. */
        if (host_accmode == O_WRONLY)
            host_accmode = O_RDWR;
    } else if (!strcmp(path, "/dev/urandom") || !strcmp(path, "/dev/random")) {
        host_dev = "/dev/urandom";
        /* Linux guests may open random devices writable, but macOS requires a
         * readable host fd for those cases.
         */
        if (host_accmode != O_RDONLY)
            host_accmode = O_RDWR;
    } else if (!strcmp(path, "/dev/tty"))
        host_dev = "/dev/tty";

    if (host_dev) {
        /* Restrict to access mode plus descriptor flags. Creation/truncation
         * flags (O_CREAT/O_TRUNC/O_EXCL) and directory/symlink semantics make
         * no sense for a character device and should not influence the host
         * open call; passing O_CREAT without a mode would also be a variadic
         * argument bug.
         */
        int oflags = host_accmode | (translate_open_flags(linux_flags) &
                                     (O_NONBLOCK | O_CLOEXEC));
        int fd = open(host_dev, oflags);
        return fd >= 0 ? fd : -1;
    }

    /* /dev/shm -> tmpfs-backed host temp directory.
     * Linux applications use /dev/shm for shm_open + mmap MAP_SHARED.
     * Redirect to one shared host namespace so named shm works across elfuse
     * processes and fork children.
     */
    if (!strcmp(path, "/dev/shm") || !strncmp(path, "/dev/shm/", 9)) {
        const char *shm = shm_dir_path();
        if (!shm)
            return -1;
        if (!strcmp(path, "/dev/shm"))
            return proc_open_dir_fd(shm, linux_flags);
        /* /dev/shm/name -> /tmp/elfuse-shm-UID/name
         * Reject any path component traversal: "..", "/", or leading "/"
         */
        const char *suffix = path + 9;
        if (strstr(suffix, "..") || strchr(suffix, '/') || suffix[0] == '\0') {
            errno = EACCES;
            return -1;
        }
        char host_path[512];
        int n = snprintf(host_path, sizeof(host_path), "%s/%s", shm, suffix);
        if (n < 0 || (size_t) n >= sizeof(host_path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        int oflags = translate_open_flags(linux_flags);
        /* O_NOFOLLOW: do not follow symlinks created by the guest inside the
         * shm directory (prevents symlink-based escape).
         */
        int fd = open(host_path, oflags | O_NOFOLLOW, mode);
        return fd >= 0 ? fd : -1;
    }

    /* /dev/stdin -> dup(0), /dev/stdout -> dup(1), /dev/stderr -> dup(2) */
    if (!strcmp(path, "/dev/stdin"))
        return dup(STDIN_FILENO);
    if (!strcmp(path, "/dev/stdout"))
        return dup(STDOUT_FILENO);
    if (!strcmp(path, "/dev/stderr"))
        return dup(STDERR_FILENO);

    /* /dev/fd/N -> dup(N) */
    if (!strncmp(path, "/dev/fd/", 8)) {
        char *endptr;
        long n = strtol(path + 8, &endptr, 10);
        if (endptr == path + 8 || *endptr != '\0' || n < 0 ||
            n >= FD_TABLE_SIZE) {
            errno = EBADF;
            return -1;
        }
        int host_fd = fd_to_host((int) n);
        if (host_fd < 0) {
            errno = EBADF;
            return -1;
        }
        return dup(host_fd);
    }

    /* /proc -> synthetic directory with PID entries for busybox ps, top, etc.
     * Creates a temp dir once (cached for the process lifetime) with entries
     * matching the current single-process model: the current PID directory +
     * "self" symlink. The DIR* created from this allows getdents64 to enumerate
     * /proc like a real procfs. Cleaned up via atexit.
     */
    if (!strcmp(path, "/proc")) {
        const char *dir = ensure_proc_tmpdir(g);
        if (!dir)
            return -1;
        int fd = proc_open_dir_fd(dir, linux_flags);
        return fd >= 0 ? fd : -1;
    }

    /* /proc/self -> directory fd for the PID subdirectory */
    if (!strcmp(path, "/proc/self") || !strcmp(path, "/proc/self/")) {
        const char *dir = ensure_proc_tmpdir(g);
        if (!dir)
            return -1;
        int fd = proc_open_numbered_dir(dir, proc_get_pid(), linux_flags);
        return fd >= 0 ? fd : -1;
    }

    /* /proc/self/fd -> directory listing of guest-visible file descriptors.
     * Use a persistent temp directory because macOS getdents-backed callers
     * need real directory entries for fchdir/readdir to work.
     */
    if (!strcmp(path, "/proc/self/fd") || !strcmp(path, "/proc/self/fd/")) {
        pthread_mutex_lock(&fddir_lock);
        if (fddir[0] == '\0') {
            if (proc_lazy_mkdtemp(fddir, sizeof(fddir),
                                  "/tmp/elfuse-fd-XXXXXX") < 0) {
                pthread_mutex_unlock(&fddir_lock);
                return -1;
            }
            atexit(cleanup_fddir);
        }

        for (int i = 0; i < FD_TABLE_SIZE; i++) {
            char entry[192];
            snprintf(entry, sizeof(entry), "%s/%d", fddir, i);
            fd_entry_t snap;
            if (fd_snapshot(i, &snap)) {
                int tfd = open(entry, O_CREAT | O_WRONLY, 0444);
                if (tfd >= 0)
                    close(tfd);
            } else {
                unlink(entry);
            }
        }

        int fd = proc_open_dir_fd(fddir, linux_flags);
        pthread_mutex_unlock(&fddir_lock);
        return fd >= 0 ? fd : -1;
    }

    /* /proc/<pid>/stat -> redirect to /proc/self/stat for the current PID */
    if (!strncmp(path, "/proc/", 6)) {
        char *endp;
        long pid = strtol(path + 6, &endp, 10);
        if (endp != path + 6 && pid == (long) proc_get_pid()) {
            /* Rewrite /proc/<our_pid>/X to /proc/self/X and recurse */
            if (!strncmp(endp, "/stat", 5) && endp[5] == '\0')
                return proc_intercept_open(g, "/proc/self/stat", linux_flags,
                                           mode);
            if (!strncmp(endp, "/status", 7) && endp[7] == '\0')
                return proc_intercept_open(g, "/proc/self/status", linux_flags,
                                           mode);
            if (!strncmp(endp, "/cmdline", 8) && endp[8] == '\0')
                return proc_intercept_open(g, "/proc/self/cmdline", linux_flags,
                                           mode);
            if (!strncmp(endp, "/exe", 4) && endp[4] == '\0')
                return proc_intercept_open(g, "/proc/self/exe", linux_flags,
                                           mode);
            if (!strncmp(endp, "/environ", 8) && endp[8] == '\0')
                return proc_intercept_open(g, "/proc/self/environ", linux_flags,
                                           mode);
            if (!strncmp(endp, "/auxv", 5) && endp[5] == '\0')
                return proc_intercept_open(g, "/proc/self/auxv", linux_flags,
                                           mode);
            if (!strncmp(endp, "/task", 5) &&
                (endp[5] == '\0' || endp[5] == '/')) {
                char redir[128];
                snprintf(redir, sizeof(redir), "/proc/self/task%s", endp + 5);
                return proc_intercept_open(g, redir, linux_flags, mode);
            }
            if (!strncmp(endp, "/fd", 3) &&
                (endp[3] == '\0' || endp[3] == '/')) {
                char redir[128];
                snprintf(redir, sizeof(redir), "/proc/self/fd%s", endp + 3);
                return proc_intercept_open(g, redir, linux_flags, mode);
            }
            if (!strcmp(endp, "") || !strcmp(endp, "/")) {
                const char *dir = ensure_proc_tmpdir(g);
                if (!dir)
                    return -1;
                int fd =
                    proc_open_numbered_dir(dir, proc_get_pid(), linux_flags);
                return fd >= 0 ? fd : -1;
            }
        }
    }

    /* /proc/self/exe -> open the actual ELF binary.
     * Unlike readlinkat (which returns the path string), openat needs to
     * return an actual file descriptor to the binary.
     */
    if (!strcmp(path, "/proc/self/exe")) {
        const char *exe = proc_get_elf_path();
        if (!exe) {
            errno = ENOENT;
            return -1;
        }
        int fd = open(exe, O_RDONLY);
        return fd >= 0 ? fd : -1;
    }

    /* /proc/cpuinfo -> synthetic file with CPU count.
     * Buffer sized dynamically from ncpu (~200 bytes/entry) to avoid
     * silent truncation on hosts with >16 CPUs.
     */
    if (!strcmp(path, "/proc/cpuinfo")) {
        int ncpu = (int) sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1)
            ncpu = 1;
        size_t bufsz = (size_t) ncpu * 256 + 64;
        char stackbuf[4096];
        char *buf = (bufsz <= sizeof(stackbuf)) ? stackbuf : malloc(bufsz);
        if (!buf)
            return -1;
        int off = 0;
        for (int i = 0; i < ncpu && off < (int) bufsz - 256; i++) {
            off += snprintf(
                buf + off, bufsz - off,
                "processor\t: %d\n"
                "BogoMIPS\t: 48.00\n"
                "Features\t: fp asimd aes pmull sha1 sha2 crc32 atomics\n"
                "CPU implementer\t: 0x61\n"
                "CPU architecture: 8\n"
                "CPU variant\t: 0x1\n"
                "CPU part\t: 0x022\n"
                "CPU revision\t: 1\n\n",
                i);
        }
        int fd = proc_synthetic_fd(buf, off);
        if (buf != stackbuf)
            free(buf);
        return fd;
    }

    /* /proc/self/status -> synthetic process status */
    if (!strcmp(path, "/proc/self/status")) {
        /* Compute VmSize from region tracking (total virtual memory) */
        uint64_t vm_size_kb = 0;
        for (int i = 0; i < g->nregions; i++)
            vm_size_kb += (g->regions[i].end - g->regions[i].start);
        vm_size_kb /= 1024;

        /* VmRSS: approximate as non-PROT_NONE regions (HVF cannot query actual
         * residency from HVF, but mapped != PROT_NONE is close)
         */
        uint64_t vm_rss_kb = 0;
        for (int i = 0; i < g->nregions; i++) {
            if (g->regions[i].prot != 0) /* PROT_NONE = 0 */
                vm_rss_kb += (g->regions[i].end - g->regions[i].start);
        }
        vm_rss_kb /= 1024;

        /* Extract basename from ELF path for the Name field (Linux uses the
         * comm name, which is basename truncated to 15 chars)
         */
        const char *exe = proc_get_elf_path();
        const char *name = "elfuse";
        if (exe) {
            const char *slash = strrchr(exe, '/');
            name = slash ? slash + 1 : exe;
        }

        int threads = thread_active_count();
        char buf[2048];
        int len = snprintf(
            buf, sizeof(buf),
            "Name:\t%.15s\n"
            "State:\tR (running)\n"
            "Tgid:\t%lld\n"
            "Pid:\t%lld\n"
            "PPid:\t%lld\n"
            "Uid:\t%d\t%d\t%d\t%d\n"
            "Gid:\t%d\t%d\t%d\t%d\n"
            "VmPeak:\t%llu kB\n"
            "VmSize:\t%llu kB\n"
            "VmRSS:\t%llu kB\n"
            "Threads:\t%d\n",
            name, (long long) proc_get_pid(), (long long) proc_get_pid(),
            (long long) proc_get_ppid(), GUEST_UID, GUEST_UID, GUEST_UID,
            GUEST_UID, GUEST_GID, GUEST_GID, GUEST_GID, GUEST_GID,
            (unsigned long long) vm_size_kb, (unsigned long long) vm_size_kb,
            (unsigned long long) vm_rss_kb, threads);
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    /* /proc/self/limits -> resource limits from prlimit64 cache */
    if (!strcmp(path, "/proc/self/limits")) {
        char buf[2048];
        int len = sys_format_limits(buf, sizeof(buf));
        if (len <= 0)
            return proc_synthetic_fd("", 0);
        return proc_synthetic_fd(buf, len);
    }

    /* /proc/self/cmdline -> NUL-separated argv */
    if (!strcmp(path, "/proc/self/cmdline")) {
        size_t len;
        const char *data = proc_get_cmdline(&len);
        if (!data)
            return proc_synthetic_fd("", 0);
        return proc_synthetic_fd(data, len);
    }

    /* /proc/self/environ -> NUL-separated environment variables */
    if (!strcmp(path, "/proc/self/environ")) {
        size_t len;
        const char *data = proc_get_environ(&len);
        if (!data)
            return proc_synthetic_fd("", 0);
        return proc_synthetic_fd(data, len);
    }

    /* /proc/self/auxv -> raw auxiliary vector (key-value uint64 pairs) */
    if (!strcmp(path, "/proc/self/auxv")) {
        size_t len;
        const void *data = proc_get_auxv(&len);
        if (!data)
            return proc_synthetic_fd("", 0);
        return proc_synthetic_fd(data, len);
    }

    /* /proc/self/task -> directory with per-thread TID entries.
     * Debuggers and runtimes (GDB, LLDB, JVM, Go runtime) probe this at
     * startup to discover thread count and per-thread state.
     *
     * Rebuilds a temp directory on each open (thread set is dynamic).
     * Cannot rmdir before returning the fd because macOS getdents on unlinked
     * dirs returns empty. Uses a static path cleaned up at exit.
     */
    if (!strcmp(path, "/proc/self/task") || !strcmp(path, "/proc/self/task/")) {
        static char taskdir[128];
        static pthread_mutex_t taskdir_lock = PTHREAD_MUTEX_INITIALIZER;

        pthread_mutex_lock(&taskdir_lock);
        if (proc_lazy_mkdtemp(taskdir, sizeof(taskdir),
                              "/tmp/elfuse-task-XXXXXX") < 0) {
            pthread_mutex_unlock(&taskdir_lock);
            return -1;
        }

        int64_t tids[MAX_THREADS];
        proc_task_collect_ctx_t ctx = {tids, 0};
        thread_for_each(proc_task_collect_cb, &ctx);

        for (int i = 0; i < ctx.ntids; i++) {
            char tidpath[128];
            snprintf(tidpath, sizeof(tidpath), "%s/%lld", taskdir,
                     (long long) tids[i]);
            mkdir(tidpath, 0755);
        }

        int fd = proc_open_dir_fd(taskdir, linux_flags);
        pthread_mutex_unlock(&taskdir_lock);

        return fd >= 0 ? fd : -1;
    }

    /* /proc/self/task/<tid>/stat -> per-thread stat line */
    if (!strncmp(path, "/proc/self/task/", 16)) {
        char *endp;
        long tid = strtol(path + 16, &endp, 10);
        if (endp == path + 16 || tid <= 0)
            return -2; /* not intercepted */

        /* Verify this TID is actually active */
        if (!thread_tid_alive((int64_t) tid)) {
            errno = ENOENT;
            return -1;
        }

        if (!strcmp(endp, "/stat")) {
            const char *exe = proc_get_elf_path();
            const char *name = "elfuse";
            if (exe) {
                const char *slash = strrchr(exe, '/');
                name = slash ? slash + 1 : exe;
            }
            char buf[512];
            int len =
                snprintf(buf, sizeof(buf),
                         "%ld (%.15s) R %lld %lld %lld 0 0 0 0 0 0 0 0 0 0 0 "
                         "20 0 %d 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
                         "0 0 0 0 0 0 0 0\n",
                         tid, name, (long long) proc_get_ppid(),
                         (long long) proc_get_pid(), /* pgid */
                         (long long) proc_get_sid(), thread_active_count());
            return proc_synthetic_fd_str(buf, len, sizeof(buf));
        }

        if (!strcmp(endp, "/status")) {
            const char *exe = proc_get_elf_path();
            const char *name = "elfuse";
            if (exe) {
                const char *slash = strrchr(exe, '/');
                name = slash ? slash + 1 : exe;
            }
            char buf[1024];
            int len =
                snprintf(buf, sizeof(buf),
                         "Name:\t%.15s\n"
                         "State:\tR (running)\n"
                         "Tgid:\t%lld\n"
                         "Pid:\t%ld\n"
                         "PPid:\t%lld\n"
                         "Uid:\t%d\t%d\t%d\t%d\n"
                         "Gid:\t%d\t%d\t%d\t%d\n"
                         "Threads:\t%d\n",
                         name, (long long) proc_get_pid(), tid,
                         (long long) proc_get_ppid(), GUEST_UID, GUEST_UID,
                         GUEST_UID, GUEST_UID, GUEST_GID, GUEST_GID, GUEST_GID,
                         GUEST_GID, thread_active_count());
            return proc_synthetic_fd_str(buf, len, sizeof(buf));
        }

        /* /proc/self/task/<tid> directory itself */
        if (*endp == '\0' || !strcmp(endp, "/")) {
            /* Return a synthetic directory with stat/status placeholder
             * entries. Uses a persistent temp dir (not cleaned until process
             * exit) so getdents sees entries on macOS.
             */
            static char tiddir_base[128];
            static pthread_mutex_t tiddir_lock = PTHREAD_MUTEX_INITIALIZER;

            pthread_mutex_lock(&tiddir_lock);
            if (proc_lazy_mkdtemp(tiddir_base, sizeof(tiddir_base),
                                  "/tmp/elfuse-tid-XXXXXX") < 0) {
                pthread_mutex_unlock(&tiddir_lock);
                return -1;
            }

            char p[160];
            snprintf(p, sizeof(p), "%s/stat", tiddir_base);
            close(open(p, O_CREAT | O_WRONLY, 0444));
            snprintf(p, sizeof(p), "%s/status", tiddir_base);
            close(open(p, O_CREAT | O_WRONLY, 0444));

            int fd = proc_open_dir_fd(tiddir_base, linux_flags);
            pthread_mutex_unlock(&tiddir_lock);

            return fd >= 0 ? fd : -1;
        }

        return -2; /* unknown /proc/self/task/<tid>/XXX */
    }

    /* /proc/self/maps -> generated from guest region tracking.
     * Addresses are page-aligned (rounded down/up) to match real Linux
     * behavior. Output merges consecutive regions with the same prot, flags,
     * and name into a single maps line, matching real Linux kernel behavior
     * where a single mmap() call produces one maps entry even when the backing
     * pages span multiple physical frames.
     */
    if (!strcmp(path, "/proc/self/maps")) {
        char buf[16384];
        int off = 0;

        /* Build a flat array of (va_start, va_end, prot, flags, offset, name)
         * from regions[] with merging.
         */
        typedef struct {
            uint64_t start, end;
            int prot, flags;
            uint64_t offset;
            char name[64];
        } maps_entry_t;
        maps_entry_t entries[MAPS_ENTRY_MAX];
        int nentries = 0;

        /* Convert regions[] to maps entries (identity-mapped) */
        for (int i = 0; i < g->nregions && nentries < MAPS_ENTRY_MAX - 1; i++) {
            const guest_region_t *r = &g->regions[i];
            uint64_t start = r->start & ~0xFFFULL;
            uint64_t end = (r->end + 0xFFF) & ~0xFFFULL;

            /* Try to merge with previous entry if contiguous and same
             * prot/flags/name. This collapses many 2 MiB blocks into a single
             * maps line, matching real Linux kernel behavior.
             */
            if (nentries > 0) {
                maps_entry_t *prev = &entries[nentries - 1];
                if (start == prev->end && r->prot == prev->prot &&
                    r->flags == prev->flags && !strcmp(r->name, prev->name)) {
                    prev->end = end;
                    continue;
                }
            }

            maps_entry_t *e = &entries[nentries++];
            e->start = start;
            e->end = end;
            e->prot = r->prot;
            e->flags = r->flags;
            e->offset = r->offset;
            if (r->name[0]) {
                str_copy_trunc(e->name, r->name, sizeof(e->name));
            } else {
                e->name[0] = '\0';
            }
        }

        /* Emit lines after merging so buffer accounting is centralized. */
        for (int i = 0; i < nentries && off < (int) sizeof(buf) - 256; i++) {
            const maps_entry_t *e = &entries[i];
            char perms[5];
            perms[0] = (e->prot & 0x1) ? 'r' : '-';
            perms[1] = (e->prot & 0x2) ? 'w' : '-';
            perms[2] = (e->prot & 0x4) ? 'x' : '-';
            perms[3] = (e->flags & 0x01) ? 's' : 'p';
            perms[4] = '\0';

            /* Format matches real Linux /proc/<pid>/maps exactly:
             *   %lx-%lx %s %08lx %02x:%02x %lu  <padding>  %s\n
             * Verified against strace in a real Lima VZ VM.
             */
            char line[256];
            int lineoff = snprintf(
                line, sizeof(line), "%llx-%llx %s %08llx 00:00 0",
                (unsigned long long) e->start, (unsigned long long) e->end,
                perms, (unsigned long long) e->offset);
            /* Cap lineoff to buffer size (snprintf may return more
             * than available on truncation)
             */
            if (lineoff >= (int) sizeof(line))
                lineoff = (int) sizeof(line) - 1;
            if (e->name[0]) {
                while (lineoff < MAPS_NAME_COLUMN &&
                       lineoff < (int) sizeof(line) - 1)
                    line[lineoff++] = ' ';
                int n = snprintf(line + lineoff, sizeof(line) - lineoff, "%s",
                                 e->name);
                if (n > 0)
                    lineoff += n;
                if (lineoff >= (int) sizeof(line))
                    lineoff = (int) sizeof(line) - 1;
            } else if (lineoff < (int) sizeof(line) - 1) {
                line[lineoff++] = ' ';
            }
            int wrote =
                snprintf(buf + off, sizeof(buf) - off, "%.*s\n", lineoff, line);
            if (wrote > 0 && off + wrote < (int) sizeof(buf))
                off += wrote;
            else
                break; /* Stop before truncating a maps line. */
        }

        log_debug("/proc/self/maps (%d bytes):\n%.*s", off, off, buf);
        return proc_synthetic_fd(buf, off);
    }

    /* /proc/uptime -> synthetic uptime in seconds.
     * Uses sysctl(KERN_BOOTTIME), same as sys_sysinfo() in syscall/sys.c.
     * Idle time is 0 (no meaningful macOS equivalent).
     */
    if (!strcmp(path, "/proc/uptime")) {
        struct timeval boottime;
        size_t bt_len = sizeof(boottime);
        int mib[2] = {CTL_KERN, KERN_BOOTTIME};
        if (sysctl(mib, 2, &boottime, &bt_len, NULL, 0) < 0)
            return -1;
        struct timeval now;
        gettimeofday(&now, NULL);
        double uptime = (double) (now.tv_sec - boottime.tv_sec) +
                        (double) (now.tv_usec - boottime.tv_usec) / 1e6;
        char buf[128];
        int len = snprintf(buf, sizeof(buf), "%.2f 0.00\n", uptime);
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    /* /proc/loadavg -> synthetic load averages.
     * Musl's getloadavg() reads /proc/loadavg, so GNU uptime needs this.
     */
    if (!strcmp(path, "/proc/loadavg")) {
        double loadavg[3] = {0};
        getloadavg(loadavg, 3);
        char buf[128];
        int len =
            snprintf(buf, sizeof(buf), "%.2f %.2f %.2f 1/1 %lld\n", loadavg[0],
                     loadavg[1], loadavg[2], (long long) proc_get_pid());
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    /* /var/run/utmp, /run/utmp -> synthetic utmp with current user.
     * Creates one USER_PROCESS record for who, users, pinky.
     */
    if (!strcmp(path, "/var/run/utmp") || !strcmp(path, "/run/utmp")) {
        _Static_assert(sizeof(linux_utmpx_t) == 400,
                       "linux_utmpx_t size mismatch");
        linux_utmpx_t entry;
        memset(&entry, 0, sizeof(entry));
        entry.ut_type = LINUX_USER_PROCESS;
        entry.ut_pid = (int32_t) proc_get_pid();
        str_copy_trunc(entry.ut_line, "pts/0", sizeof(entry.ut_line));
        str_copy_trunc(entry.ut_id, "0", sizeof(entry.ut_id));
        const char *user = getenv("USER");
        if (!user)
            user = "user";
        str_copy_trunc(entry.ut_user, user, sizeof(entry.ut_user));
        str_copy_trunc(entry.ut_host, "localhost", sizeof(entry.ut_host));
        struct timeval now;
        gettimeofday(&now, NULL);
        entry.ut_tv_sec = now.tv_sec;
        entry.ut_tv_usec = now.tv_usec;
        return proc_synthetic_fd(&entry, sizeof(entry));
    }

    /* /proc/net: live socket tables.
     * Enumerates sockets from the local FD table AND from all active fork-child
     * processes via macOS proc_pidfdinfo().  This gives system-wide visibility
     * matching real Linux /proc/net semantics.
     */
    if (!strcmp(path, "/proc/net/tcp") || !strcmp(path, "/proc/net/tcp6") ||
        !strcmp(path, "/proc/net/udp") || !strcmp(path, "/proc/net/udp6") ||
        !strcmp(path, "/proc/net/raw") || !strcmp(path, "/proc/net/raw6")) {
        bool want_tcp = !!strstr(path, "tcp"), want_udp = !!strstr(path, "udp");
        bool want_v6 = (path[strlen(path) - 1] == '6');
        int want_af = want_v6 ? AF_INET6 : AF_INET;
        int want_stype = want_tcp   ? SOCK_STREAM
                         : want_udp ? SOCK_DGRAM
                                    : SOCK_RAW;
        const char *header_fmt =
            want_tcp ? "  sl  local_address rem_address   st tx_queue "
                       "rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                     : "  sl  local_address rem_address   st tx_queue "
                       "rx_queue tr tm->when retrnsmt   uid  timeout inode"
                       " ref pointer drops\n";
        char buf[16384];
        int off = snprintf(buf, sizeof(buf), "%s", header_fmt);

        /* Collect PIDs to scan: self + active children */
        pid_t pids[PROC_TABLE_SIZE + 1];
        pids[0] = getpid();
        int npids = 1 + proc_get_child_pids(pids + 1, PROC_TABLE_SIZE);

        int sl = 0;
        for (int p = 0; p < npids && off < (int) sizeof(buf) - 256; p++) {
            struct proc_fdinfo fdinfo[512];
            int fdsz = proc_pidinfo(pids[p], PROC_PIDLISTFDS, 0, fdinfo,
                                    sizeof(fdinfo));
            if (fdsz <= 0)
                continue;
            int nfds = fdsz / (int) PROC_PIDLISTFD_SIZE;

            for (int fi = 0; fi < nfds && off < (int) sizeof(buf) - 256; fi++) {
                if (fdinfo[fi].proc_fdtype != PROX_FDTYPE_SOCKET)
                    continue;

                struct socket_fdinfo sinfo;
                int sz =
                    proc_pidfdinfo(pids[p], fdinfo[fi].proc_fd,
                                   PROC_PIDFDSOCKETINFO, &sinfo, sizeof(sinfo));
                if (sz < (int) sizeof(sinfo))
                    continue;

                int saf = sinfo.psi.soi_family, stype = sinfo.psi.soi_type;
                if (saf != want_af || stype != want_stype)
                    continue;

                uint16_t lport = 0, rport = 0;
                char laddr[33], raddr[33];
                const struct in_sockinfo *ini =
                    want_tcp ? &sinfo.psi.soi_proto.pri_tcp.tcpsi_ini
                             : &sinfo.psi.soi_proto.pri_in;

                format_proc_net_addr(laddr, ini, 1, want_v6);
                lport = ntohs(ini->insi_lport);
                format_proc_net_addr(raddr, ini, 0, want_v6);
                rport = ntohs(ini->insi_fport);

                /* TCP state from the kernel's tcp_connection_info */
                int st = 0x07; /* TCP_CLOSE default */
                if (want_tcp) {
                    int kstate = sinfo.psi.soi_proto.pri_tcp.tcpsi_state;
                    /* macOS TSI_S_* matches Linux TCP state encoding:
                     * 0=CLOSED, 1=LISTEN, 2=SYN_SENT, etc. But Linux
                     * /proc/net uses 1-based: 01=ESTABLISHED, 0A=LISTEN
                     */
                    static const int state_map[] = {
                        0x07, /* 0: CLOSED */
                        0x0A, /* 1: LISTEN */
                        0x02, /* 2: SYN_SENT */
                        0x03, /* 3: SYN_RECEIVED */
                        0x01, /* 4: ESTABLISHED */
                        0x08, /* 5: CLOSE_WAIT */
                        0x04, /* 6: FIN_WAIT_1 */
                        0x06, /* 7: CLOSING */
                        0x09, /* 8: LAST_ACK */
                        0x05, /* 9: FIN_WAIT_2 */
                        0x0B, /* 10: TIME_WAIT */
                    };
                    if (RANGE_CHECK(kstate, 0, 11))
                        st = state_map[kstate];
                }

                off = append_proc_net_row(buf, sizeof(buf), off, want_tcp, sl,
                                          laddr, lport, raddr, rport, st);
                sl++;
            }
        }
        return proc_synthetic_fd_str(buf, off, sizeof(buf));
    }
    if (!strcmp(path, "/proc/net/unix")) {
        char buf[8192];
        int off = snprintf(buf, sizeof(buf),
                           "Num       RefCount Protocol Flags    Type St "
                           "Inode Path\n");

        pid_t pids[PROC_TABLE_SIZE + 1];
        pids[0] = getpid();
        int npids = 1 + proc_get_child_pids(pids + 1, PROC_TABLE_SIZE);

        for (int p = 0; p < npids && off < (int) sizeof(buf) - 128; p++) {
            struct proc_fdinfo fdinfo[512];
            int fdsz = proc_pidinfo(pids[p], PROC_PIDLISTFDS, 0, fdinfo,
                                    sizeof(fdinfo));
            if (fdsz <= 0)
                continue;
            int nfds = fdsz / (int) PROC_PIDLISTFD_SIZE;

            for (int fi = 0; fi < nfds && off < (int) sizeof(buf) - 128; fi++) {
                if (fdinfo[fi].proc_fdtype != PROX_FDTYPE_SOCKET)
                    continue;
                struct socket_fdinfo sinfo;
                int sz =
                    proc_pidfdinfo(pids[p], fdinfo[fi].proc_fd,
                                   PROC_PIDFDSOCKETINFO, &sinfo, sizeof(sinfo));
                if (sz < (int) sizeof(sinfo))
                    continue;
                if (sinfo.psi.soi_family != AF_UNIX)
                    continue;
                int stype = sinfo.psi.soi_type;
                int lt = (stype == SOCK_STREAM)      ? 1
                         : (stype == SOCK_DGRAM)     ? 2
                         : (stype == SOCK_SEQPACKET) ? 5
                                                     : 1;
                /* Unix socket path from soi_proto.pri_un.unsi_addr */
                const char *spath =
                    sinfo.psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_path;
                off +=
                    snprintf(buf + off, sizeof(buf) - off,
                             "%016X: %08X %08X %08X %04X %02X %5d %s\n", 0, 3,
                             0, 0, lt, 3, 10000 + fi, spath[0] ? spath : "");
            }
        }
        return proc_synthetic_fd_str(buf, off, sizeof(buf));
    }

    /* /proc/sys/vm/mmap_min_addr -> synthetic mmap minimum address. */
    if (!strcmp(path, "/proc/sys/vm/mmap_min_addr")) {
        const char *data = "32768\n";
        return proc_synthetic_fd(data, strlen(data));
    }

    /* /proc/sys/kernel/randomize_va_space -> ASLR enabled (full). */
    if (!strcmp(path, "/proc/sys/kernel/randomize_va_space")) {
        const char *data = "2\n";
        return proc_synthetic_fd(data, strlen(data));
    }

    /* /proc/version -> synthetic kernel version string */
    if (!strcmp(path, "/proc/version")) {
        char buf[256];
        int len = snprintf(buf, sizeof(buf),
                           "Linux version 6.17.0-20-generic "
                           "(buildd@bos03-arm64-051) "
                           "(aarch64-linux-gnu-gcc (Ubuntu 15.2.0-4ubuntu4) "
                           "15.2.0, GNU ld (GNU Binutils for Ubuntu) 2.45) "
                           "#20-Ubuntu SMP PREEMPT_DYNAMIC\n");
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    /* /proc/filesystems -> supported filesystem types */
    if (!strcmp(path, "/proc/filesystems")) {
        const char *data =
            "\tmpfs\n"
            "\tproc\n"
            "\tsysfs\n"
            "\tdevtmpfs\n"
            "\text4\n"
            "\tvfat\n";
        return proc_synthetic_fd(data, strlen(data));
    }

    /* /proc/self/mountinfo -> Linux mountinfo format (different from
     * /proc/mounts). Format: id parent_id major:minor root mount_point options
     * - type source super_options
     */
    if (!strcmp(path, "/proc/self/mountinfo")) {
        char buf[1024];
        int len =
            snprintf(buf, sizeof(buf),
                     "1 0 0:1 / / rw,relatime - ext4 /dev/root rw\n"
                     "2 1 0:2 / /proc rw,nosuid,nodev,noexec - proc proc rw\n"
                     "3 1 0:3 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n"
                     "4 1 0:4 / /dev rw,nosuid - devtmpfs devtmpfs rw\n"
                     "5 4 0:5 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw\n");
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    /* /proc/mounts, /etc/mtab -> synthetic mount table */
    if (!strcmp(path, "/proc/mounts") || !strcmp(path, "/proc/self/mounts") ||
        !strcmp(path, "/etc/mtab")) {
        char buf[512];
        int len = snprintf(buf, sizeof(buf),
                           "/ / ext4 rw,relatime 0 0\n"
                           "proc /proc proc rw,nosuid,nodev,noexec 0 0\n"
                           "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"
                           "devtmpfs /dev devtmpfs rw,nosuid 0 0\n"
                           "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n");
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    /* /proc/self/oom_score_adj -> writable stub.
     * Containers and systemd write this; accept writes and return
     * last-written value (default 0).
     */
    if (proc_is_oom_path(path)) {
        int val = atomic_load(&oom_score_adj_value);
        char buf[32];
        int len = snprintf(buf, sizeof(buf), "%d\n", val);
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    /* /proc/self/fdinfo/<N> -> per-fd flags/pos/mnt_id */
    if (!strncmp(path, "/proc/self/fdinfo/", 18)) {
        char *endptr;
        long n = strtol(path + 18, &endptr, 10);
        if (endptr == path + 18 || *endptr != '\0' || n < 0 ||
            n >= FD_TABLE_SIZE) {
            errno = ENOENT;
            return -1;
        }
        fd_entry_t snap;
        if (!fd_snapshot((int) n, &snap)) {
            errno = ENOENT;
            return -1;
        }
        off_t pos = 0;
        int host_fd = fd_to_host((int) n);
        if (host_fd >= 0)
            pos = lseek(host_fd, 0, SEEK_CUR);
        if (pos < 0)
            pos = 0;
        int flags = snap.linux_flags;
        char buf[256];
        int len = snprintf(buf, sizeof(buf),
                           "pos:\t%lld\n"
                           "flags:\t0%o\n"
                           "mnt_id:\t0\n",
                           (long long) pos, flags);
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    /* /proc/self/fdinfo -> directory listing via persistent temp dir (macOS
     * getdents needs real directory entries).
     */
    if (!strcmp(path, "/proc/self/fdinfo") ||
        !strcmp(path, "/proc/self/fdinfo/")) {
        static char fdinfodir[128];
        static pthread_mutex_t fdinfodir_lock = PTHREAD_MUTEX_INITIALIZER;

        pthread_mutex_lock(&fdinfodir_lock);
        if (proc_lazy_mkdtemp(fdinfodir, sizeof(fdinfodir),
                              "/tmp/elfuse-fdinfo-XXXXXX") < 0) {
            pthread_mutex_unlock(&fdinfodir_lock);
            return -1;
        }

        for (int i = 0; i < FD_TABLE_SIZE; i++) {
            char entry[192];
            snprintf(entry, sizeof(entry), "%s/%d", fdinfodir, i);
            fd_entry_t snap;
            if (fd_snapshot(i, &snap)) {
                int tfd = open(entry, O_CREAT | O_WRONLY, 0444);
                if (tfd >= 0)
                    close(tfd);
            } else {
                unlink(entry);
            }
        }

        int fd = proc_open_dir_fd(fdinfodir, linux_flags);
        pthread_mutex_unlock(&fdinfodir_lock);
        return fd >= 0 ? fd : -1;
    }

    /* /proc/self/fd/N -> open the target of the fd (readlink-style) */
    if (!strncmp(path, "/proc/self/fd/", 14)) {
        char *endptr;
        long n = strtol(path + 14, &endptr, 10);
        if (endptr == path + 14 || *endptr != '\0' || n < 0 ||
            n >= FD_TABLE_SIZE) {
            errno = EBADF;
            return -1;
        }
        int host_fd = fd_to_host((int) n);
        if (host_fd < 0) {
            errno = EBADF;
            return -1;
        }
        return dup(host_fd);
    }

    /* /proc/meminfo -> synthetic memory info from host vm_statistics */
    if (!strcmp(path, "/proc/meminfo")) {
        int64_t physmem = 0;
        size_t sz = sizeof(physmem);
        int mib[2] = {CTL_HW, HW_MEMSIZE};
        sysctl(mib, 2, &physmem, &sz, NULL, 0);
        uint64_t total_kb = (uint64_t) physmem / 1024;

        /* Query host vm_statistics for accurate free/active/inactive.
         * Falls back to approximations if the mach call fails.
         */
        uint64_t free_kb, avail_kb, buffers_kb, cached_kb;
        vm_statistics64_data_t vm_stat = {0};
        mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
        uint64_t page_size = 4096;
        if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                              (host_info64_t) &vm_stat,
                              &count) == KERN_SUCCESS) {
            host_page_size(mach_host_self(), (vm_size_t *) &page_size);
            free_kb = (uint64_t) vm_stat.free_count * page_size / 1024;
            uint64_t inactive_kb =
                (uint64_t) vm_stat.inactive_count * page_size / 1024;
            uint64_t purgeable_kb =
                (uint64_t) vm_stat.purgeable_count * page_size / 1024;
            /* Available ≈ free + inactive + purgeable (Linux heuristic) */
            avail_kb = free_kb + inactive_kb + purgeable_kb;
            if (avail_kb > total_kb)
                avail_kb = total_kb;
            cached_kb = inactive_kb + purgeable_kb;
            buffers_kb = 0; /* macOS does not expose buffer cache separately */
        } else {
            free_kb = total_kb / 2;
            avail_kb = total_kb * 3 / 4;
            buffers_kb = total_kb / 20;
            cached_kb = total_kb / 4;
        }
        char buf[2048];
        int len = snprintf(
            buf, sizeof(buf),
            "MemTotal:       %llu kB\n"
            "MemFree:        %llu kB\n"
            "MemAvailable:   %llu kB\n"
            "Buffers:        %llu kB\n"
            "Cached:         %llu kB\n"
            "SwapCached:     0 kB\n"
            "Active:         %llu kB\n"
            "Inactive:       %llu kB\n"
            "SwapTotal:      0 kB\n"
            "SwapFree:       0 kB\n"
            "Dirty:          0 kB\n"
            "Writeback:      0 kB\n"
            "AnonPages:      %llu kB\n"
            "Mapped:         %llu kB\n"
            "Shmem:          0 kB\n"
            "Slab:           0 kB\n"
            "SReclaimable:   0 kB\n"
            "SUnreclaim:     0 kB\n"
            "KernelStack:    0 kB\n"
            "PageTables:     0 kB\n"
            "CommitLimit:    %llu kB\n"
            "Committed_AS:   0 kB\n"
            "VmallocTotal:   0 kB\n"
            "VmallocUsed:    0 kB\n"
            "VmallocChunk:   0 kB\n",
            (unsigned long long) total_kb, (unsigned long long) free_kb,
            (unsigned long long) avail_kb, (unsigned long long) buffers_kb,
            (unsigned long long) cached_kb,
            (unsigned long long) (total_kb - free_kb - cached_kb),
            (unsigned long long) (cached_kb / 2),
            (unsigned long long) (total_kb - free_kb - cached_kb - buffers_kb),
            (unsigned long long) (cached_kb / 2),
            (unsigned long long) (total_kb / 2));
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    /* /proc/self/io -> synthetic I/O counters.
     * Some node-style observability runtimes read this for resource
     * monitoring metrics. procfs emulation returns zeroed counters because
     * it does not track per-guest I/O.
     */
    if (!strcmp(path, "/proc/self/io")) {
        static const char data[] =
            "rchar: 0\n"
            "wchar: 0\n"
            "syscr: 0\n"
            "syscw: 0\n"
            "read_bytes: 0\n"
            "write_bytes: 0\n"
            "cancelled_write_bytes: 0\n";
        return proc_synthetic_fd(data, sizeof(data) - 1);
    }

    /* /proc/self/stat -> single-line process stat (man 5 proc).
     * Managed runtimes read this for resource monitoring (utime, stime, rss,
     * vsize).
     * Format: pid (comm) state ppid pgrp session tty_nr tpgid flags ...
     * Fields populated with meaningful values: pid, comm, state, ppid,
     * utime(14), stime(15), vsize(23), rss(24). Rest are zero/defaults.
     */
    if (!strcmp(path, "/proc/self/stat")) {
        /* Get process CPU times for utime/stime fields */
        struct rusage ru;
        getrusage(RUSAGE_SELF, &ru);
        /* Convert to clock ticks (Linux USER_HZ = 100) */
        long utime_ticks =
            ru.ru_utime.tv_sec * 100 + ru.ru_utime.tv_usec / 10000;
        long stime_ticks =
            ru.ru_stime.tv_sec * 100 + ru.ru_stime.tv_usec / 10000;

        /* Compute vsize and rss from guest region tracking */
        uint64_t vsize = 0, rss_pages = 0;
        long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0)
            page_size = 4096;
        for (int i = 0; i < g->nregions; i++) {
            uint64_t sz = g->regions[i].end - g->regions[i].start;
            vsize += sz;
            if (g->regions[i].prot != 0) /* non-PROT_NONE = resident */
                rss_pages += sz / (uint64_t) page_size;
        }

        const char *exe = proc_get_elf_path();
        const char *comm = "elfuse";
        if (exe) {
            const char *slash = strrchr(exe, '/');
            comm = slash ? slash + 1 : exe;
        }

        char buf[1024];
        /* Fields: pid(1) (comm)(2) state(3) ppid(4) pgrp(5) session(6)
         *   tty_nr(7) tpgid(8) flags(9) minflt(10) cminflt(11) majflt(12)
         *   cmajflt(13) utime(14) stime(15) cutime(16) cstime(17)
         *   priority(18) nice(19) num_threads(20) itrealvalue(21)
         *   starttime(22) vsize(23) rss(24) rsslim(25) ... (52 fields total)
         */
        int len = snprintf(
            buf, sizeof(buf),
            "%lld (%.15s) R %lld %lld %lld 0 -1 0 "        /* 1-9 */
            "0 0 0 0 %ld %ld 0 0 "                         /* 10-17 */
            "20 0 %d 0 0 %llu %llu "                       /* 18-24 */
            "18446744073709551615 0 0 0 0 0 0 "            /* 25-31 */
            "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", /* 32-52 */
            (long long) proc_get_pid(), comm, (long long) proc_get_ppid(),
            (long long) proc_get_pid(), /* pgrp = pid */
            (long long) proc_get_pid(), /* session = pid */
            utime_ticks, stime_ticks, thread_active_count(),
            (unsigned long long) vsize, (unsigned long long) rss_pages);
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    /* /proc/stat -> synthetic CPU statistics */
    if (!strcmp(path, "/proc/stat")) {
        struct timeval boottime;
        size_t bt_len = sizeof(boottime);
        int mib[2] = {CTL_KERN, KERN_BOOTTIME};
        sysctl(mib, 2, &boottime, &bt_len, NULL, 0);
        int ncpu = (int) sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1)
            ncpu = 1;
        char buf[4096];
        int off = 0;
        /* Aggregate CPU line (user, nice, system, idle, iowait, irq, softirq)
         */
        off += snprintf(buf + off, sizeof(buf) - off,
                        "cpu  1000 0 500 50000 0 0 0 0 0 0\n");
        /* Per-CPU lines */
        for (int i = 0; i < ncpu && off < (int) sizeof(buf) - 128; i++) {
            off += snprintf(buf + off, sizeof(buf) - off,
                            "cpu%d 100 0 50 5000 0 0 0 0 0 0\n", i);
        }
        off += snprintf(buf + off, sizeof(buf) - (size_t) off,
                        "intr 0\n"
                        "ctxt 0\n"
                        "btime %lld\n"
                        "processes 1\n"
                        "procs_running 1\n"
                        "procs_blocked 0\n",
                        (long long) boottime.tv_sec);
        if (off > (int) sizeof(buf))
            off = (int) sizeof(buf);
        return proc_synthetic_fd(buf, off);
    }

    /* /etc/passwd -> synthetic passwd with root + current user */
    if (!strcmp(path, "/etc/passwd")) {
        char buf[512];
        int len = snprintf(buf, sizeof(buf),
                           "root:x:0:0:root:/root:/bin/sh\n"
                           "user:x:1000:1000:user:/home/user:/bin/sh\n");
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    /* /etc/group -> synthetic group file */
    if (!strcmp(path, "/etc/group")) {
        char buf[512];
        int len = snprintf(buf, sizeof(buf),
                           "root:x:0:\n"
                           "staff:x:20:\n"
                           "user:x:1000:\n");
        return proc_synthetic_fd_str(buf, len, sizeof(buf));
    }

    return PROC_NOT_INTERCEPTED;
}

int proc_intercept_stat(const char *path, struct stat *st)
{
    /* Intercept stat for /proc paths emulated via proc_intercept_open.
     * Without this, runtime libraries that probe a file's existence via stat()
     * before opening it would fail on synthetic /proc paths (e.g., a stat() of
     * /proc/self/io would return ENOENT before the caller ever issues open()).
     *
     * procfs emulation returns a minimal regular file stat. Exact values are
     * irrelevant here; callers need stat to succeed before opening the
     * synthetic file.
     */
    /* /dev/shm is a directory */
    if (!strcmp(path, "/dev/shm") || !strcmp(path, "/dev/shm/")) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFDIR | 01777; /* sticky bit, like real /dev/shm */
        st->st_nlink = 2;
        return 0;
    }
    /* /dev/shm/<name> files: check the host temp dir */
    if (!strncmp(path, "/dev/shm/", 9)) {
        const char *shm = shm_dir_path();
        if (!shm)
            return -1;
        const char *suffix = path + 9;
        if (strstr(suffix, "..") || strchr(suffix, '/') || suffix[0] == '\0') {
            errno = EACCES;
            return -1;
        }
        char host_path[512];
        int n = snprintf(host_path, sizeof(host_path), "%s/%s", shm, suffix);
        if (n < 0 || (size_t) n >= sizeof(host_path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return stat(host_path, st);
    }

    /* /proc and /proc/<our_pid> are directories */
    if (!strcmp(path, "/proc") || !strcmp(path, "/proc/")) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFDIR | 0555;
        st->st_nlink = 3;
        return 0;
    }
    {
        char pidbuf[32], pidslash[32];
        snprintf(pidbuf, sizeof(pidbuf), "/proc/%lld",
                 (long long) proc_get_pid());
        snprintf(pidslash, sizeof(pidslash), "/proc/%lld/",
                 (long long) proc_get_pid());
        if (!strcmp(path, pidbuf) || !strcmp(path, pidslash) ||
            !strcmp(path, "/proc/self") || !strcmp(path, "/proc/self/")) {
            memset(st, 0, sizeof(*st));
            st->st_mode = S_IFDIR | 0555;
            st->st_nlink = 3;
            return 0;
        }
    }

    /* /proc/<our_pid>/<file> -> treat as /proc/self/<file> */
    if (!strncmp(path, "/proc/", 6)) {
        char *endp;
        long pid = strtol(path + 6, &endp, 10);
        if (endp != path + 6 && pid == (long) proc_get_pid() && *endp == '/') {
            char alias[LINUX_PATH_MAX];
            snprintf(alias, sizeof(alias), "/proc/self%s", endp);
            return proc_intercept_stat(alias, st);
        }
    }

    /* /proc/self/task and /proc/self/task/<tid> are directories */
    if (!strcmp(path, "/proc/self/task") || !strcmp(path, "/proc/self/task/")) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFDIR | 0555;
        st->st_nlink = 2 + thread_active_count();
        return 0;
    }
    if (!strncmp(path, "/proc/self/task/", 16)) {
        char *endp;
        long tid = strtol(path + 16, &endp, 10);
        if (endp != path + 16 && tid > 0) {
            if (!thread_tid_alive((int64_t) tid)) {
                errno = ENOENT;
                return -1;
            }
            if (*endp == '\0' || !strcmp(endp, "/")) {
                /* /proc/self/task/<tid> directory */
                memset(st, 0, sizeof(*st));
                st->st_mode = S_IFDIR | 0555;
                st->st_nlink = 2;
                return 0;
            }
            if (!strcmp(endp, "/stat") || !strcmp(endp, "/status")) {
                memset(st, 0, sizeof(*st));
                st->st_mode = S_IFREG | 0444;
                st->st_nlink = 1;
                st->st_size = 256;
                st->st_blksize = 4096;
                st->st_blocks = 1;
                return 0;
            }
        }
    }

    if (proc_is_oom_path(path)) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = 2;
        st->st_blksize = 4096;
        st->st_blocks = 1;
        return 0;
    }

    if (!strcmp(path, "/proc/self/fdinfo") ||
        !strcmp(path, "/proc/self/fdinfo/")) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFDIR | 0555;
        st->st_nlink = 2;
        return 0;
    }

    if (!strcmp(path, "/proc/self/fd") || !strcmp(path, "/proc/self/fd/")) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFDIR | 0555;
        st->st_nlink = 2;
        return 0;
    }

    if (!strncmp(path, "/proc/self/fdinfo/", 18)) {
        char *endp;
        long fd = strtol(path + 18, &endp, 10);
        if (endp == path + 18 || *endp != '\0' || fd < 0 ||
            fd >= FD_TABLE_SIZE) {
            errno = ENOENT;
            return -1;
        }
        fd_entry_t snap;
        if (!fd_snapshot((int) fd, &snap)) {
            errno = ENOENT;
            return -1;
        }
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = 32;
        st->st_blksize = 4096;
        st->st_blocks = 1;
        return 0;
    }

    static const char *known_proc_files[] = {
        "/proc/self/io",
        "/proc/self/stat",
        "/proc/self/status",
        "/proc/self/cmdline",
        "/proc/self/maps",
        "/proc/self/exe",
        "/proc/self/environ",
        "/proc/self/auxv",
        "/proc/self/mountinfo",
        "/proc/self/mounts",
        "/proc/cpuinfo",
        "/proc/meminfo",
        "/proc/stat",
        "/proc/uptime",
        "/proc/loadavg",
        "/proc/version",
        "/proc/filesystems",
        "/proc/sys/vm/mmap_min_addr",
        "/proc/sys/kernel/randomize_va_space",
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
        "/proc/net/raw",
        "/proc/net/raw6",
        "/proc/net/unix",
        NULL,
    };

    for (const char **p = known_proc_files; *p; p++) {
        if (!strcmp(path, *p)) {
            memset(st, 0, sizeof(*st));
            st->st_mode = S_IFREG | 0444; /* Regular file, read-only */
            st->st_nlink = 1;
            st->st_size = 256; /* Approximate; exact value not critical */
            st->st_blksize = 4096;
            st->st_blocks = 1;
            return 0;
        }
    }

    /* /proc/self/fd/N: stat the underlying host fd */
    if (!strncmp(path, "/proc/self/fd/", 14)) {
        char *endptr;
        long n = strtol(path + 14, &endptr, 10);
        if (endptr == path + 14 || *endptr != '\0' || n < 0 ||
            n >= FD_TABLE_SIZE) {
            errno = EBADF;
            return -1;
        }
        int host_fd = fd_to_host((int) n);
        if (host_fd < 0) {
            errno = EBADF;
            return -1;
        }
        if (fstat(host_fd, st) < 0)
            return -1;
        return 0;
    }

    return PROC_NOT_INTERCEPTED;
}

int proc_intercept_readlink(const char *path, char *buf, size_t bufsiz)
{
    /* /proc/self/exe -> path of current ELF binary */
    if (!strcmp(path, "/proc/self/exe")) {
        const char *exe = proc_get_elf_path();
        if (!exe) {
            errno = ENOENT;
            return -1;
        }
        size_t len = strlen(exe);
        if (len > bufsiz)
            len = bufsiz;
        memcpy(buf, exe, len);
        return (int) len;
    }

    /* /proc/self/cwd -> getcwd() */
    if (!strcmp(path, "/proc/self/cwd")) {
        proc_cwd_view_t view;
        if (proc_acquire_cwd_view(&view) < 0)
            return -1;
        size_t copy_len = view.len;
        if (copy_len > bufsiz)
            copy_len = bufsiz;
        memcpy(buf, view.path, copy_len);
        proc_release_cwd_view(&view);
        return (int) copy_len;
    }

    /* /proc/self/fd/N -> path of host fd (via fcntl F_GETPATH on macOS) */
    if (!strncmp(path, "/proc/self/fd/", 14)) {
        char *endptr;
        long n = strtol(path + 14, &endptr, 10);
        if (endptr == path + 14 || *endptr != '\0' || n < 0 ||
            n >= FD_TABLE_SIZE) {
            errno = EBADF;
            return -1;
        }
        int host_fd = fd_to_host((int) n);
        if (host_fd < 0) {
            errno = EBADF;
            return -1;
        }

        char fdpath[MAXPATHLEN];
        if (fcntl(host_fd, F_GETPATH, fdpath) < 0) {
            errno = ENOENT;
            return -1;
        }
        size_t len = strlen(fdpath);
        if (len > bufsiz)
            len = bufsiz;
        memcpy(buf, fdpath, len);
        return (int) len;
    }

    return PROC_NOT_INTERCEPTED;
}

int proc_intercept_write(int guest_fd,
                         int host_fd,
                         const void *buf,
                         size_t count,
                         int64_t offset,
                         int use_pwrite,
                         ssize_t *written_out)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap))
        return 0;
    if (!proc_is_oom_writable(snap.proc_path))
        return 0;

    int val;
    if (proc_parse_int_write(buf, count, &val) < 0)
        return -1;
    if (val < -1000 || val > 1000) {
        errno = EINVAL;
        return -1;
    }

    atomic_store(&oom_score_adj_value, val);

    char text[32];
    int len = snprintf(text, sizeof(text), "%d\n", val);
    if (len < 0) {
        errno = EINVAL;
        return -1;
    }

    if (ftruncate(host_fd, 0) < 0)
        return -1;
    if (pwrite(host_fd, text, (size_t) len, 0) != len)
        return -1;
    if (!use_pwrite && lseek(host_fd, offset + (int64_t) count, SEEK_SET) < 0)
        return -1;

    *written_out = (ssize_t) count;
    return 1;
}
