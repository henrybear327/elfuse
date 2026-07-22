/*
 * Sysroot path-translation matrix
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Table-driven coverage of the path-taking syscalls against guest-created
 * fixtures whose names exercise the casefold sidecar: every op must resolve
 * the same file through absolute, cwd-relative, dirfd-relative, nested, and
 * symlinked spellings, report ENOENT for wrong-case spellings, and never
 * leak on-disk sidecar artifacts to the guest. Run under --sysroot with
 * argv[1] = "ci" (case-insensitive volume, sidecar active) or "cs"
 * (case-sensitive volume, sidecar inert); argv[2] optionally names a staged
 * host file outside the sysroot for the host-fallback rows. The binary
 * re-execs itself with --phase2 to assert resolution and cwd reconstruction
 * survive fork+execve.
 *
 * Known gaps assert as expected failures: an XFAIL line counts as pass, an
 * XPASS fails the run so a fixing commit must delete the marker.
 *   XF_OPENAT2_WALK: openat2 RESOLVE_* prechecks walk raw guest components
 *   and cannot see sidecar tokens.
 *   XF_SENDTO_ABS: sendto skips the abstract-socket rewrite for
 *   destination addresses.
 *   XF_REL_TOKENWALK: a cwd-relative path with tokenized intermediate
 *   components does not resolve; only the leaf is sidecar-walked.
 *   XF_SYMLINK_TOKENDIR, XF_MKNOD_TOKENDIR: the sidecar has no symlinkat
 *   or mknodat writers, so creating either inside a guest-created
 *   (tokenized) directory fails.
 *   XF_SYMLINK_TOKENTARGET: the host kernel follows symlink targets, so a
 *   target crossing tokenized components does not resolve.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;
static int xfails = 0;

static bool mode_ci = true;
/* native: running on a real Linux kernel (qemu parity lane). The elfuse
 * known-gap cells flip from expected-failure to must-pass, proving each gap
 * is an elfuse-ism and the table never encodes one as Linux truth.
 */
static bool mode_native = false;

/* Guest-created fixtures; mixed-case names get sidecar tokens on a casefold
 * sysroot, so every access below crosses the translation layer.
 */
#define DIR_A "/DirA"
#define DIR_B DIR_A "/SubB"
#define FILE_C DIR_B "/File.C"
#define FILE_C_REL "DirA/SubB/File.C"
#define FILE_C_WRONG "/dira/subb/file.c"
/* Symlink and FIFO fixtures live in the sysroot root: the root is host
 * staged (never tokenized), and the sidecar cannot create either inside a
 * tokenized directory (XF_SYMLINK_TOKENDIR / XF_MKNOD_TOKENDIR below).
 */
#define SYM_L "/Sym.Link"
#define FIFO_F "/Fifo.Mixed"
/* Four nested guest-created levels: each becomes a 21-byte token component
 * on a casefold sysroot, so host spellings under this chain exceed the
 * 104-byte macOS sun_path while the guest spelling stays well under the
 * 108-byte Linux limit.
 */
#define DEEP_DIR "/Deep.A/Deep.B/Deep.C/Deep.D"

static void xfail_result(const char *id, bool op_succeeded)
{
    if (mode_native) {
        TEST(id);
        EXPECT_TRUE(op_succeeded, "must pass on a real kernel");
        return;
    }
    if (op_succeeded) {
        printf("XPASS %s (delete the marker in the fixing commit)\n", id);
        fails++;
    } else {
        printf("XFAIL %s\n", id);
        xfails++;
    }
}

static int write_file(const char *path, const char *content)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, content, strlen(content));
    close(fd);
    return n == (ssize_t) strlen(content) ? 0 : -1;
}

static void fixtures_create(void)
{
    TEST("fixture mkdir nested mixed");
    EXPECT_TRUE(mkdir(DIR_A, 0755) == 0 && mkdir(DIR_B, 0755) == 0,
                "mkdir fixtures");

    TEST("fixture create file");
    EXPECT_TRUE(write_file(FILE_C, "matrix\n") == 0, "create " FILE_C);

    TEST("fixture mknod fifo");
    EXPECT_TRUE(mknod(FIFO_F, S_IFIFO | 0644, 0) == 0, "mknod fifo");

    /* Target the FIFO: mknod has no sidecar writer, so the FIFO keeps its
     * real on-disk name and the host kernel can follow the link. A target
     * crossing tokenized components is a walk gap (XF_SYMLINK_TOKENTARGET).
     */
    TEST("fixture symlink rel target");
    EXPECT_TRUE(symlink("Fifo.Mixed", SYM_L) == 0, "symlink");

    if (mode_ci) {
        xfail_result("XF_SYMLINK_TOKENDIR",
                     symlink("SubB/File.C", DIR_A "/Tok.Sym") == 0);
        xfail_result("XF_MKNOD_TOKENDIR",
                     mknod(DIR_A "/Tok.Fifo", S_IFIFO | 0644, 0) == 0);
    }
}

/* Forward resolution: one file, five spellings, every lookup verb. */

static void section_forward(const char *host_file)
{
    struct stat st;

    TEST("stat absolute nested");
    EXPECT_TRUE(stat(FILE_C, &st) == 0 && st.st_size == 7, "stat abs");

    TEST("stat wrong case ENOENT");
    EXPECT_ERRNO(stat(FILE_C_WRONG, &st), ENOENT, "wrong case must miss");

    /* Multi-component relative resolution with tokenized intermediates is a
     * known walk gap; leaf-only relative names work from inside the dir.
     */
    if (mode_ci) {
        int rfd = open(FILE_C_REL, O_RDONLY);
        xfail_result("XF_REL_TOKENWALK", rfd >= 0);
        if (rfd >= 0)
            close(rfd);
    }

    TEST("leaf-relative open in cwd");
    int fd = -1;
    bool leaf_ok = chdir(DIR_B) == 0 && (fd = open("File.C", O_RDONLY)) >= 0 &&
                   access("File.C", R_OK) == 0 && chdir("/") == 0;
    EXPECT_TRUE(leaf_ok, "leaf relative open+access");
    if (fd >= 0)
        close(fd);

    TEST("openat dirfd-relative");
    int dirfd = open(DIR_A, O_RDONLY | O_DIRECTORY);
    EXPECT_TRUE(dirfd >= 0, "open " DIR_A);
    if (dirfd >= 0) {
        TEST("fstatat dirfd-relative");
        EXPECT_TRUE(
            fstatat(dirfd, "SubB/File.C", &st, 0) == 0 && st.st_size == 7,
            "fstatat dirfd");

        TEST("faccessat dirfd-relative");
        EXPECT_TRUE(faccessat(dirfd, "SubB/File.C", R_OK, 0) == 0,
                    "faccessat dirfd");

        TEST("fstatat wrong case dirfd");
        EXPECT_ERRNO(fstatat(dirfd, "subb/file.c", &st, 0), ENOENT,
                     "dirfd wrong case");
        close(dirfd);
    }

    TEST("stat via symlink");
    EXPECT_TRUE(stat(SYM_L, &st) == 0 && S_ISFIFO(st.st_mode),
                "follow symlink to fifo");

    bool tok_ok = symlink("DirA/SubB/File.C", "/Tok.Target") == 0 &&
                  stat("/Tok.Target", &st) == 0 && st.st_size == 7;
    if (mode_ci) {
        xfail_result("XF_SYMLINK_TOKENTARGET", tok_ok);
    } else {
        TEST("stat via symlink nested");
        EXPECT_TRUE(tok_ok, "symlink to nested target");
    }

    /* Symlinks are the only guest-created entries stored under their real
     * names, so absolute-path unlink of one exercises the exact-name scan,
     * which must find the entry regardless of its directory offset.
     */
    TEST("unlink symlink absolute");
    EXPECT_TRUE(unlink("/Tok.Target") == 0, "absolute symlink unlink");

    TEST("readlink exact bytes");
    char buf[256];
    ssize_t n = readlink(SYM_L, buf, sizeof(buf) - 1);
    EXPECT_TRUE(n == (ssize_t) strlen("Fifo.Mixed") &&
                    memcmp(buf, "Fifo.Mixed", (size_t) n) == 0,
                "readlink content untranslated");

    TEST("readlinkat dirfd-relative");
    int rootfd = open("/", O_RDONLY | O_DIRECTORY);
    char rlbuf[64];
    ssize_t rln = rootfd >= 0
                      ? readlinkat(rootfd, "Sym.Link", rlbuf, sizeof(rlbuf) - 1)
                      : -1;
    EXPECT_TRUE(rln == (ssize_t) strlen("Fifo.Mixed") &&
                    memcmp(rlbuf, "Fifo.Mixed", (size_t) rln) == 0,
                "readlinkat dirfd content");
    if (rootfd >= 0)
        close(rootfd);

    TEST("lstat symlink NOFOLLOW");
    EXPECT_TRUE(lstat(SYM_L, &st) == 0 && S_ISLNK(st.st_mode), "lstat");

    TEST("statfs on fixture dir");
    struct statfs sf;
    EXPECT_TRUE(statfs(DIR_A, &sf) == 0 && sf.f_bsize > 0, "statfs");

    TEST("statx absolute");
    struct statx stx;
    EXPECT_TRUE(statx(AT_FDCWD, FILE_C, 0, STATX_BASIC_STATS, &stx) == 0 &&
                    stx.stx_size == 7,
                "statx");

    if (host_file) {
        TEST("host-fallback read");
        fd = open(host_file, O_RDONLY);
        EXPECT_TRUE(fd >= 0, "host fallback open");
        if (fd >= 0)
            close(fd);
    }

    if (mode_ci) {
        TEST("reserved index invisible");
        EXPECT_ERRNO(stat(DIR_A "/.elfuse_case_index", &st), ENOENT,
                     "index file must be hidden");

        TEST("reserved name uncreatable");
        EXPECT_ERRNO(
            open(DIR_A "/.elfuse_case_index", O_CREAT | O_WRONLY, 0644), ENOENT,
            "index name must be uncreatable");
    }
}

/* Metadata verbs on tokenized names: metadata syscalls must reach the host
 * with the sidecar token spelling, not the raw guest name.
 */
static void section_metadata(void)
{
    struct stat st;

    TEST("chmod absolute");
    EXPECT_TRUE(chmod(FILE_C, 0640) == 0 && stat(FILE_C, &st) == 0 &&
                    (st.st_mode & 07777) == 0640,
                "chmod round-trip");

    TEST("chown identity overlay");
    EXPECT_TRUE(chown(FILE_C, getuid(), getgid()) == 0, "chown");

    TEST("utimensat absolute");
    struct timespec ts[2] = {{1234567, 0}, {1234567, 0}};
    EXPECT_TRUE(utimensat(AT_FDCWD, FILE_C, ts, 0) == 0 &&
                    stat(FILE_C, &st) == 0 && st.st_mtime == 1234567,
                "utimensat round-trip");

    TEST("truncate absolute");
    EXPECT_TRUE(
        truncate(FILE_C, 3) == 0 && stat(FILE_C, &st) == 0 && st.st_size == 3,
        "truncate");

    TEST("xattr set/get/remove");
    bool xok = setxattr(FILE_C, "user.matrix", "v1", 2, 0) == 0;
    char xv[8] = {0};
    xok = xok && getxattr(FILE_C, "user.matrix", xv, sizeof(xv)) == 2 &&
          memcmp(xv, "v1", 2) == 0;
    char xl[64];
    ssize_t xn = xok ? listxattr(FILE_C, xl, sizeof(xl)) : -1;
    xok = xok && xn > 0 && memmem(xl, (size_t) xn, "user.matrix", 11) != NULL;
    xok = xok && removexattr(FILE_C, "user.matrix") == 0;
    EXPECT_TRUE(xok, "xattr quartet");

    /* AT_EMPTY_PATH: the shared resolver path. */
    int ofd = open(FILE_C, O_PATH);
    TEST("fstatat AT_EMPTY_PATH O_PATH");
    EXPECT_TRUE(ofd >= 0 && fstatat(ofd, "", &st, AT_EMPTY_PATH) == 0 &&
                    st.st_size == 3,
                "empty-path stat");

    TEST("fchownat AT_EMPTY_PATH");
    EXPECT_TRUE(
        ofd >= 0 && fchownat(ofd, "", getuid(), getgid(), AT_EMPTY_PATH) == 0,
        "empty-path chown");

    /* fchmodat2 goes through the same shared resolver; kernels before 6.6
     * lack the syscall, so ENOSYS passes on the native lane.
     */
    TEST("fchmodat2 AT_EMPTY_PATH");
    long cr = ofd >= 0 ? syscall(452 /* __NR_fchmodat2 */, ofd, "", 0600,
                                 AT_EMPTY_PATH)
                       : -1;
    bool chmod_ok = cr == 0 && fstatat(ofd, "", &st, AT_EMPTY_PATH) == 0 &&
                    (st.st_mode & 07777) == 0600;
    if (mode_native && cr == -1 && errno == ENOSYS)
        chmod_ok = true;
    EXPECT_TRUE(chmod_ok, "empty-path chmod");
    if (ofd >= 0)
        close(ofd);

    /* Linux resolves AT_FDCWD + AT_EMPTY_PATH in a search-only cwd; an
     * O_RDONLY-based resolver would fail it with EACCES. Meaningless as
     * root (native lane runs as root and bypasses the mode bits).
     */
    if (!mode_native) {
        TEST("statx empty-path search-only cwd");
        struct statx psx;
        bool perm_ok =
            mkdir("/Perm.Dir", 0755) == 0 && chdir("/Perm.Dir") == 0 &&
            chmod("/Perm.Dir", 0311) == 0 &&
            statx(AT_FDCWD, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &psx) == 0 &&
            S_ISDIR(psx.stx_mode);
        EXPECT_TRUE(perm_ok, "search-only cwd statx");
        chmod("/Perm.Dir", 0755);
        chdir("/");
    }
}

/* Mutations through the sidecar writer walk, via dirfd. */

static void section_mutations(void)
{
    struct stat st;
    int dirfd = open(DIR_A, O_RDONLY | O_DIRECTORY);
    TEST("mutation dirfd open");
    EXPECT_TRUE(dirfd >= 0, "open dir");
    if (dirfd < 0)
        return;

    TEST("mkdirat mixed case");
    EXPECT_TRUE(mkdirat(dirfd, "New.Sub", 0755) == 0 &&
                    fstatat(dirfd, "New.Sub", &st, 0) == 0 &&
                    S_ISDIR(st.st_mode),
                "mkdirat");

    TEST("mknodat fifo dirfd");
    EXPECT_TRUE(mknodat(dirfd, "Fifo.Two", S_IFIFO | 0644, 0) == 0 &&
                    fstatat(dirfd, "Fifo.Two", &st, 0) == 0 &&
                    S_ISFIFO(st.st_mode),
                "mknodat");

    TEST("linkat hard link");
    EXPECT_TRUE(linkat(AT_FDCWD, FILE_C, dirfd, "Hard.Link", 0) == 0 &&
                    fstatat(dirfd, "Hard.Link", &st, 0) == 0 &&
                    st.st_nlink == 2,
                "linkat nlink");

    TEST("renameat within dir");
    EXPECT_TRUE(write_file(DIR_A "/Ren.Src", "r\n") == 0 &&
                    renameat(dirfd, "Ren.Src", dirfd, "Ren.Dst") == 0 &&
                    fstatat(dirfd, "Ren.Dst", &st, 0) == 0,
                "renameat");

    TEST("rename old name gone");
    EXPECT_ERRNO(fstatat(dirfd, "Ren.Src", &st, 0), ENOENT, "src stays gone");

    TEST("renameat2 NOREPLACE EEXIST");
    EXPECT_ERRNO((long) syscall(SYS_renameat2, dirfd, "Ren.Dst", dirfd,
                                "Hard.Link", 1 /* RENAME_NOREPLACE */),
                 EEXIST, "NOREPLACE");

    TEST("renameat across tokenized dirs");
    int subfd = openat(dirfd, "New.Sub", O_RDONLY | O_DIRECTORY);
    bool cross_ok = subfd >= 0 && write_file(DIR_A "/Cross.Src", "x\n") == 0 &&
                    renameat(dirfd, "Cross.Src", subfd, "Cross.Dst") == 0 &&
                    fstatat(subfd, "Cross.Dst", &st, 0) == 0 &&
                    fstatat(dirfd, "Cross.Src", &st, 0) == -1 &&
                    errno == ENOENT;
    EXPECT_TRUE(cross_ok, "cross-dir rename");
    if (subfd >= 0)
        close(subfd);

    /* RENAME_EXCHANGE swaps two tokenized names; the host backend supports
     * it for absolute AT_FDCWD paths only (renamex_np takes no dirfds).
     */
    TEST("renameat2 EXCHANGE absolute");
    bool ex_ok = write_file(DIR_A "/Ex.One", "1\n") == 0 &&
                 write_file(DIR_A "/Ex.Two", "22\n") == 0 &&
                 syscall(SYS_renameat2, AT_FDCWD, DIR_A "/Ex.One", AT_FDCWD,
                         DIR_A "/Ex.Two", 2 /* RENAME_EXCHANGE */) == 0 &&
                 stat(DIR_A "/Ex.One", &st) == 0 && st.st_size == 3 &&
                 stat(DIR_A "/Ex.Two", &st) == 0 && st.st_size == 2;
    EXPECT_TRUE(ex_ok, "exchange swaps contents");

    TEST("unlinkat then ENOENT");
    EXPECT_TRUE(unlinkat(dirfd, "Ren.Dst", 0) == 0 &&
                    fstatat(dirfd, "Ren.Dst", &st, 0) == -1 && errno == ENOENT,
                "unlinkat");

    TEST("wrong-case unlink ENOENT");
    EXPECT_ERRNO(unlinkat(dirfd, "hard.link", 0), ENOENT,
                 "fold-blind unlink must miss");

    close(dirfd);
}

/* Reverse direction: host state becoming guest-visible names. */

static void section_reverse(void)
{
    TEST("chdir + getcwd guest names");
    char cwd[512] = {0};
    bool ok = chdir(DIR_B) == 0 && getcwd(cwd, sizeof(cwd)) != NULL &&
              strcmp(cwd, DIR_B) == 0;
    EXPECT_TRUE(ok, "getcwd exact");

    TEST("/proc/self/cwd guest names");
    char pbuf[512] = {0};
    ssize_t n = readlink("/proc/self/cwd", pbuf, sizeof(pbuf) - 1);
    EXPECT_TRUE(n > 0 && strcmp(pbuf, DIR_B) == 0, "proc cwd exact");

    TEST("cwd has no token");
    EXPECT_TRUE(strstr(cwd, ".ef_") == NULL && strstr(pbuf, ".ef_") == NULL,
                "no .ef_ leak");
    chdir("/");

    TEST("readdir shows guest names");
    DIR *d = opendir(DIR_A);
    bool saw_sub = false, leak = false;
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (!strcmp(de->d_name, "SubB"))
                saw_sub = true;
            if (strstr(de->d_name, ".ef_") ||
                strstr(de->d_name, ".elfuse_case_index"))
                leak = true;
        }
        closedir(d);
    }
    EXPECT_TRUE(d && saw_sub && !leak, "guest dirents only");

    TEST("readdir root fixtures");
    d = opendir("/");
    bool saw_sym = false, saw_dir = false;
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (!strcmp(de->d_name, "Sym.Link"))
                saw_sym = true;
            if (!strcmp(de->d_name, "DirA"))
                saw_dir = true;
        }
        closedir(d);
    }
    EXPECT_TRUE(d && saw_sym && saw_dir, "root listing exact names");

    /* fd-based directory change: the cwd reverse map must reconstruct guest
     * names without ever having seen a path argument.
     */
    TEST("fchdir + getcwd guest names");
    int dfd = open(DIR_B, O_RDONLY | O_DIRECTORY);
    char fcwd[512] = {0}, fproc[512] = {0};
    bool fok = dfd >= 0 && fchdir(dfd) == 0 &&
               getcwd(fcwd, sizeof(fcwd)) != NULL && strcmp(fcwd, DIR_B) == 0;
    ssize_t fn = readlink("/proc/self/cwd", fproc, sizeof(fproc) - 1);
    EXPECT_TRUE(fok && fn > 0 && strcmp(fproc, DIR_B) == 0 &&
                    strstr(fcwd, ".ef_") == NULL,
                "fchdir cwd exact");
    if (dfd >= 0)
        close(dfd);
    chdir("/");

    TEST("/proc/self/fd guest path");
    int fd = open(FILE_C, O_RDONLY);
    char link[64], target[512] = {0};
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    n = readlink(link, target, sizeof(target) - 1);
    EXPECT_TRUE(fd >= 0 && n > 0 && strstr(target, ".ef_") == NULL &&
                    strstr(target, "File.C") != NULL,
                "fd readlink guest spelling");
    if (fd >= 0)
        close(fd);
}

/* Pathname AF_UNIX sockets through translation. */

static void section_sockets(void)
{
    TEST("unix bind in sysroot dir");
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sun = {0};
    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, DIR_A "/Sock.Path");
    bool ok = sfd >= 0 &&
              bind(sfd, (struct sockaddr *) &sun, sizeof(sun)) == 0 &&
              listen(sfd, 1) == 0;
    EXPECT_TRUE(ok, "bind+listen");

    TEST("getsockname guest spelling");
    struct sockaddr_un got = {0};
    socklen_t got_len = sizeof(got);
    EXPECT_TRUE(sfd >= 0 &&
                    getsockname(sfd, (struct sockaddr *) &got, &got_len) == 0 &&
                    strcmp(got.sun_path, sun.sun_path) == 0,
                "bound name round-trips");

    TEST("unix connect same path");
    int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    EXPECT_TRUE(
        cfd >= 0 && connect(cfd, (struct sockaddr *) &sun, sizeof(sun)) == 0,
        "connect");

    TEST("getpeername guest spelling");
    struct sockaddr_un peer = {0};
    socklen_t peer_len = sizeof(peer);
    EXPECT_TRUE(
        cfd >= 0 &&
            getpeername(cfd, (struct sockaddr *) &peer, &peer_len) == 0 &&
            strcmp(peer.sun_path, sun.sun_path) == 0,
        "peer name round-trips");
    if (cfd >= 0)
        close(cfd);
    if (sfd >= 0)
        close(sfd);

    TEST("unix dgram sendto path");
    int r = socket(AF_UNIX, SOCK_DGRAM, 0);
    int w = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un dun = {0};
    dun.sun_family = AF_UNIX;
    strcpy(dun.sun_path, DIR_A "/Dgram.Path");
    /* Bind the sender too, so received datagrams carry a source address the
     * reverse map must rewrite.
     */
    struct sockaddr_un wun = {0};
    wun.sun_family = AF_UNIX;
    strcpy(wun.sun_path, DIR_A "/Dgram.Src");
    char rbuf[4] = {0};
    struct sockaddr_un src = {0};
    socklen_t src_len = sizeof(src);
    ok = r >= 0 && w >= 0 &&
         bind(r, (struct sockaddr *) &dun, sizeof(dun)) == 0 &&
         bind(w, (struct sockaddr *) &wun, sizeof(wun)) == 0 &&
         sendto(w, "dg", 2, 0, (struct sockaddr *) &dun, sizeof(dun)) == 2 &&
         recvfrom(r, rbuf, sizeof(rbuf), 0, (struct sockaddr *) &src,
                  &src_len) == 2 &&
         memcmp(rbuf, "dg", 2) == 0;
    EXPECT_TRUE(ok, "dgram sendto via path");

    TEST("recvfrom source guest spelling");
    EXPECT_TRUE(ok && strcmp(src.sun_path, wun.sun_path) == 0,
                "source addr round-trips");

    TEST("sendmsg/recvmsg pathname");
    struct iovec siov = {.iov_base = (void *) "mg", .iov_len = 2};
    struct msghdr smh = {0};
    smh.msg_name = &dun;
    smh.msg_namelen = sizeof(dun);
    smh.msg_iov = &siov;
    smh.msg_iovlen = 1;
    char mbuf[4] = {0};
    struct iovec riov = {.iov_base = mbuf, .iov_len = sizeof(mbuf)};
    struct sockaddr_un msrc = {0};
    struct msghdr rmh = {0};
    rmh.msg_name = &msrc;
    rmh.msg_namelen = sizeof(msrc);
    rmh.msg_iov = &riov;
    rmh.msg_iovlen = 1;
    EXPECT_TRUE(r >= 0 && w >= 0 && sendmsg(w, &smh, 0) == 2 &&
                    recvmsg(r, &rmh, 0) == 2 && memcmp(mbuf, "mg", 2) == 0 &&
                    strcmp(msrc.sun_path, wun.sun_path) == 0,
                "msg round-trip guest names");
    if (r >= 0)
        close(r);
    if (w >= 0)
        close(w);

    /* Overlong host spellings: four tokenized components put the host path
     * past the 104-byte macOS sun_path, so bind must divert through the
     * shortening symlink while getsockname still reports the guest path.
     */
    TEST("unix bind overlong host path");
    bool deep_ok =
        mkdir("/Deep.A", 0755) == 0 && mkdir("/Deep.A/Deep.B", 0755) == 0 &&
        mkdir("/Deep.A/Deep.B/Deep.C", 0755) == 0 && mkdir(DEEP_DIR, 0755) == 0;
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un lun = {0};
    lun.sun_family = AF_UNIX;
    strcpy(lun.sun_path, DEEP_DIR "/Long.Sock");
    EXPECT_TRUE(deep_ok && lfd >= 0 &&
                    bind(lfd, (struct sockaddr *) &lun, sizeof(lun)) == 0 &&
                    listen(lfd, 1) == 0,
                "overlong bind+listen");

    TEST("getsockname overlong round-trip");
    struct sockaddr_un lgot = {0};
    socklen_t lgot_len = sizeof(lgot);
    EXPECT_TRUE(
        lfd >= 0 &&
            getsockname(lfd, (struct sockaddr *) &lgot, &lgot_len) == 0 &&
            strcmp(lgot.sun_path, lun.sun_path) == 0,
        "overlong bound name");

    TEST("unix connect overlong path");
    int lcfd = socket(AF_UNIX, SOCK_STREAM, 0);
    EXPECT_TRUE(
        lcfd >= 0 && connect(lcfd, (struct sockaddr *) &lun, sizeof(lun)) == 0,
        "overlong connect");
    if (lcfd >= 0)
        close(lcfd);
    if (lfd >= 0)
        close(lfd);

    /* A 105-byte guest path is Linux-legal but longer than any macOS
     * sun_path can hold, so the reverse map must rebuild the Linux sockaddr
     * directly instead of bouncing through a mac sockaddr.
     */
    TEST("bind 105-byte guest path");
    char lpath[108];
    int lplen = snprintf(lpath, sizeof(lpath), DEEP_DIR "/");
    memset(lpath + lplen, 'X', (size_t) (105 - lplen));
    lpath[105] = '\0';
    int xfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un xun = {0};
    xun.sun_family = AF_UNIX;
    strcpy(xun.sun_path, lpath);
    EXPECT_TRUE(deep_ok && xfd >= 0 &&
                    bind(xfd, (struct sockaddr *) &xun, sizeof(xun)) == 0,
                "105-byte bind");

    TEST("getsockname 105-byte round-trip");
    struct sockaddr_un xgot = {0};
    socklen_t xgot_len = sizeof(xgot);
    EXPECT_TRUE(
        xfd >= 0 &&
            getsockname(xfd, (struct sockaddr *) &xgot, &xgot_len) == 0 &&
            strcmp(xgot.sun_path, lpath) == 0,
        "105-byte bound name");
    if (xfd >= 0)
        close(xfd);

    /* Known gap: sendto never applies the abstract rewrite, so a dgram to an
     * abstract name that connect() would reach is not deliverable.
     */
    int ar = socket(AF_UNIX, SOCK_DGRAM, 0);
    int aw = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un aun = {0};
    aun.sun_family = AF_UNIX;
    memcpy(aun.sun_path, "\0matrix-abs", 11);
    socklen_t alen = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 11);
    bool abs_ok = ar >= 0 && aw >= 0 &&
                  bind(ar, (struct sockaddr *) &aun, alen) == 0 &&
                  sendto(aw, "ab", 2, 0, (struct sockaddr *) &aun, alen) == 2;
    xfail_result("XF_SENDTO_ABS", abs_ok);
    if (ar >= 0)
        close(ar);
    if (aw >= 0)
        close(aw);
}

/* inotify watches and named events on tokenized directories. */

static bool inotify_wait_named(int ifd, uint32_t mask, const char *name)
{
    for (int i = 0; i < 50; i++) {
        char evb[1024];
        ssize_t n = read(ifd, evb, sizeof(evb));
        for (ssize_t off = 0; off < n;) {
            struct inotify_event *ev = (struct inotify_event *) (evb + off);
            if ((ev->mask & mask) && ev->len && !strcmp(ev->name, name))
                return true;
            off += (ssize_t) sizeof(*ev) + ev->len;
        }
        usleep(100000);
    }
    return false;
}

static void section_inotify(void)
{
    TEST("inotify watch tokenized dir");
    int ifd = inotify_init1(IN_NONBLOCK);
    int wd =
        ifd >= 0 ? inotify_add_watch(ifd, DIR_B, IN_CREATE | IN_DELETE) : -1;
    EXPECT_TRUE(ifd >= 0 && wd >= 0, "add watch");

    TEST("inotify named IN_CREATE");
    bool named = wd >= 0 && write_file(DIR_B "/Note.New", "n\n") == 0 &&
                 inotify_wait_named(ifd, IN_CREATE, "Note.New");
    EXPECT_TRUE(named, "event carries guest name");

    /* The delete side diffs the directory snapshot: the vanished entry must
     * also come back under its guest spelling.
     */
    TEST("inotify named IN_DELETE");
    bool del_named = named && unlink(DIR_B "/Note.New") == 0 &&
                     inotify_wait_named(ifd, IN_DELETE, "Note.New");
    EXPECT_TRUE(del_named, "delete carries guest name");

    /* A sidecar token must never surface as an event name. The snapshot
     * reverse-maps token children, and a mapping failure must drop the whole
     * snapshot rather than emit the raw .ef_ token (getdents64 parity). Create
     * another mixed-case entry and confirm the event is the guest spelling with
     * no token anywhere in the stream.
     */
    TEST("inotify no token leak");
    bool leak = false, guest_named = false;
    if (ifd >= 0 && wd >= 0 && write_file(DIR_B "/Ev.Mixed", "e\n") == 0) {
        for (int i = 0; i < 50 && !guest_named; i++) {
            char evb[1024];
            ssize_t n = read(ifd, evb, sizeof(evb));
            for (ssize_t off = 0; off < n;) {
                struct inotify_event *ev = (struct inotify_event *) (evb + off);
                if (ev->len && !strncmp(ev->name, ".ef_", 4))
                    leak = true;
                if ((ev->mask & IN_CREATE) && ev->len &&
                    !strcmp(ev->name, "Ev.Mixed"))
                    guest_named = true;
                off += (ssize_t) sizeof(*ev) + ev->len;
            }
            if (!guest_named)
                usleep(100000);
        }
        unlink(DIR_B "/Ev.Mixed");
    }
    EXPECT_TRUE(guest_named && !leak, "guest spelling, no .ef_ token");
    if (ifd >= 0)
        close(ifd);
}

/* Guest-private prefix symmetry: /tmp creates were always redirected into
 * the sysroot; lookups follow the same mapping, so a created file must be
 * visible to stat, open, and readdir of the same guest spelling.
 */
static void section_private_tmp(void)
{
    struct stat st;

    TEST("/tmp create then stat");
    EXPECT_TRUE(write_file("/tmp/Prefix.Probe", "p\n") == 0 &&
                    stat("/tmp/Prefix.Probe", &st) == 0 && st.st_size == 2,
                "tmp lookup sees create");

    TEST("/tmp readdir sees create");
    DIR *td = opendir("/tmp");
    bool saw_probe = false;
    if (td) {
        struct dirent *de;
        while ((de = readdir(td)) != NULL) {
            if (!strcmp(de->d_name, "Prefix.Probe"))
                saw_probe = true;
        }
        closedir(td);
    }
    EXPECT_TRUE(td && saw_probe, "tmp listing includes create");

    TEST("/tmp open round-trip");
    char pb[4] = {0};
    int pfd = open("/tmp/Prefix.Probe", O_RDONLY);
    EXPECT_TRUE(
        pfd >= 0 && read(pfd, pb, sizeof(pb)) == 2 && memcmp(pb, "p\n", 2) == 0,
        "tmp open reads back");
    if (pfd >= 0)
        close(pfd);

    TEST("/tmp unlink");
    EXPECT_TRUE(unlink("/tmp/Prefix.Probe") == 0, "tmp unlink");
}

/* Directory part of an absolute path into out (no trailing slash); "/" for a
 * top-level entry. Used to derive the staged host dir from its file argument.
 */
static void path_dir(const char *path, char *out, size_t out_sz)
{
    size_t n = strlen(path);
    while (n > 1 && path[n - 1] != '/')
        n--;
    if (n > 1)
        n--; /* drop the separator unless it is the leading slash */
    if (n >= out_sz)
        n = out_sz - 1;
    memcpy(out, path, n);
    out[n] = '\0';
}

static bool dir_has_entry(const char *dir, const char *name)
{
    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool found = false;
    struct dirent *de;
    while ((de = readdir(d)) != NULL)
        if (!strcmp(de->d_name, name)) {
            found = true;
            break;
        }
    closedir(d);
    return found;
}

/* Guest-private prefix classification: the private mapping is decided on the
 * lexically normalized spelling and covers bare directories, not just
 * descendants. Two properties are checked: normalized spellings of a
 * guest-created private file all resolve to it, and a host file under /tmp,
 * /var/tmp, or a bare .ccache never becomes visible.
 */
static void section_private_prefix(const char *host_file,
                                   const char *tmp_shadow)
{
    if (!mode_ci)
        return; /* sidecar inert on a case-sensitive volume */
    struct stat st;

    /* Escape fences run first, while host /var/folders paths are still
     * reachable through host fallback: the /var/tmp check below creates a guest
     * /var that legitimately shadows the staged host <hostdir>/.ccache. The
     * recipe stages a real /tmp/<tmp_shadow> file and a bare <hostdir>/.ccache
     * dir; neither may become visible through the private mapping, including
     * via a non-canonical spelling.
     */
    if (tmp_shadow) {
        char canon[256], noncanon[256];
        snprintf(canon, sizeof(canon), "/tmp/%s", tmp_shadow);
        snprintf(noncanon, sizeof(noncanon), "//tmp/%s", tmp_shadow);
        TEST("host /tmp shadow hidden (canonical)");
        EXPECT_ERRNO(stat(canon, &st), ENOENT, "/tmp must not reach host");
        TEST("host /tmp shadow hidden (non-canonical)");
        EXPECT_ERRNO(stat(noncanon, &st), ENOENT, "//tmp must not reach host");
    }
    if (host_file) {
        char hostdir[512], ccpath[600];
        path_dir(host_file, hostdir, sizeof(hostdir));
        snprintf(ccpath, sizeof(ccpath), "%s/.ccache", hostdir);
        TEST("bare host .ccache not listable");
        DIR *hc = opendir(ccpath);
        if (hc)
            closedir(hc);
        EXPECT_TRUE(hc == NULL && errno == ENOENT,
                    "bare .ccache maps private, hiding host children");
    }

    TEST("/tmp non-canonical round-trip");
    bool nc = write_file("/tmp/NC.Probe", "n\n") == 0 &&
              stat("//tmp/NC.Probe", &st) == 0 &&
              stat("/./tmp/NC.Probe", &st) == 0 &&
              stat("/tmp/../tmp/NC.Probe", &st) == 0;
    EXPECT_TRUE(nc, "normalized spellings reach the private file");
    unlink("/tmp/NC.Probe");

    TEST("/var/tmp private create+list");
    bool vt = (mkdir("/var", 0755) == 0 || errno == EEXIST) &&
              (mkdir("/var/tmp", 0755) == 0 || errno == EEXIST) &&
              write_file("/var/tmp/V.Probe", "v\n") == 0;
    EXPECT_TRUE(vt && dir_has_entry("/var/tmp", "V.Probe"),
                "var/tmp lists its private child");
    unlink("/var/tmp/V.Probe");

    TEST(".ccache bare-dir lists child");
    bool cc = (mkdir("/Cache.Proj", 0755) == 0 || errno == EEXIST) &&
              (mkdir("/Cache.Proj/.ccache", 0755) == 0 || errno == EEXIST) &&
              write_file("/Cache.Proj/.ccache/Obj", "o\n") == 0;
    EXPECT_TRUE(cc && dir_has_entry("/Cache.Proj/.ccache", "Obj"),
                "bare .ccache sees its just-created child");
}

/* openat2 RESOLVE_* prechecks: sidecar-blind forward walk (known gap). */

struct open_how_compat {
    unsigned long long flags, mode, resolve;
};

static void section_openat2(void)
{
    int dirfd = open(DIR_A, O_RDONLY | O_DIRECTORY);
    struct open_how_compat how = {O_RDONLY, 0, 0x08 /* RESOLVE_BENEATH */};
    long fd = -1;
    if (dirfd >= 0) {
        fd = syscall(437 /* __NR_openat2 */, dirfd, "SubB/File.C", &how,
                     sizeof(how));
        if (mode_ci) {
            xfail_result("XF_OPENAT2_WALK", fd >= 0);
        } else {
            TEST("openat2 BENEATH cs mode");
            EXPECT_TRUE(fd >= 0, "openat2 beneath");
        }
        if (fd >= 0)
            close((int) fd);
        close(dirfd);
    }
}

/* fork + execve of a guest-created copy: translation state and cwd survive
 * both the exec of a tokenized path and the fork relaunch.
 */
/* dirfd == -1 execs via plain execve(path); anything else goes through
 * execveat(dirfd, path, flags), covering both handlers with one harness.
 */
static void exec_child_case(const char *label,
                            int dirfd,
                            const char *path,
                            int flags)
{
    TEST(label);
    pid_t pid = fork();
    if (pid == 0) {
        if (chdir(DIR_B) != 0)
            _exit(97);
        char *argv2[] = {(char *) (DIR_A "/Exec.Copy"), (char *) "--phase2",
                         NULL};
        if (dirfd == -1)
            execve(path, argv2, NULL);
        else
            syscall(SYS_execveat, dirfd, path, argv2, NULL, flags);
        _exit(98);
    }
    int status = 0;
    EXPECT_TRUE(pid > 0 && waitpid(pid, &status, 0) == pid &&
                    WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "child clean exit");
}

static void section_exec(const char *self)
{
    TEST("exec copy into tokenized dir");
    int in = open(self, O_RDONLY);
    int out = open(DIR_A "/Exec.Copy", O_CREAT | O_WRONLY | O_TRUNC, 0755);
    bool copied = in >= 0 && out >= 0;
    if (copied) {
        char buf[65536];
        ssize_t n;
        while ((n = read(in, buf, sizeof(buf))) > 0)
            if (write(out, buf, (size_t) n) != n) {
                copied = false;
                break;
            }
    }
    if (in >= 0)
        close(in);
    if (out >= 0)
        close(out);
    EXPECT_TRUE(copied, "copy self");
    if (!copied)
        return;

    /* Every exec spelling re-runs the phase2 checks in the child, so a
     * translation bypass or a token leak in /proc/self/exe fails the
     * exact-path assertion there.
     */
    exec_child_case("fork+execve tokenized path", -1, DIR_A "/Exec.Copy", 0);

    exec_child_case("execveat absolute AT_FDCWD", AT_FDCWD, DIR_A "/Exec.Copy",
                    0);

    int xdirfd = open(DIR_A, O_RDONLY | O_DIRECTORY);
    TEST("execveat dirfd open");
    EXPECT_TRUE(xdirfd >= 0, "open " DIR_A);
    if (xdirfd >= 0) {
        exec_child_case("execveat dirfd-relative", xdirfd, "Exec.Copy", 0);
        close(xdirfd);
    }

    int xfd = open(DIR_A "/Exec.Copy", O_RDONLY);
    TEST("execveat empty-path open");
    EXPECT_TRUE(xfd >= 0, "open Exec.Copy");
    if (xfd >= 0) {
        exec_child_case("execveat AT_EMPTY_PATH", xfd, "", AT_EMPTY_PATH);
        close(xfd);
    }
}

/* Re-exec'd child: assert the exec'd process sees guest spellings. */

static int phase2_checks(void)
{
    TEST("phase2 getcwd inherited");
    char cwd[512] = {0};
    EXPECT_TRUE(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, DIR_B) == 0,
                "child cwd exact");

    TEST("phase2 relative resolve");
    EXPECT_TRUE(access("File.C", R_OK) == 0, "child relative access");

    TEST("phase2 /proc/self/exe");
    char exe[512] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    EXPECT_TRUE(n > 0 && strcmp(exe, DIR_A "/Exec.Copy") == 0,
                "exe exact guest path");

    SUMMARY("test-path-matrix phase2");
    return fails > 0 ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--phase2"))
        return phase2_checks();

    if (argc > 1 && !strcmp(argv[1], "native"))
        mode_native = true;
    mode_ci = !mode_native && !(argc > 1 && !strcmp(argv[1], "cs"));
    const char *host_file = argc > 2 ? argv[2] : NULL;
    const char *tmp_shadow = argc > 3 ? argv[3] : NULL;

    printf("test-path-matrix (%s mode)\n",
           mode_native ? "native" : (mode_ci ? "ci" : "cs"));

    fixtures_create();
    section_forward(host_file);
    section_metadata();
    section_mutations();
    section_reverse();
    section_sockets();
    section_inotify();
    section_private_tmp();
    section_openat2();
    section_exec(argv[0]);
    /* Runs last: it creates a guest /var, which legitimately shadows the host
     * /var/folders sysroot path that section_exec opens through argv[0], so it
     * must not precede any section that still needs host-side fallback.
     */
    section_private_prefix(host_file, tmp_shadow);

    printf("\nexpected failures: %d\n", xfails);
    SUMMARY("test-path-matrix");
    return fails > 0 ? 1 : 0;
}
