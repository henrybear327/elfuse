/*
 * Native-host unit test for case-exact path resolution
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives casefold_resolve_at against a real directory, because the questions it
 * answers are questions about the filesystem: does this name exist spelled the
 * way the guest asked, is its slot taken by something spelled differently, and
 * where would it have to live if it were created. A guest test could reach the
 * same code, but only through a whole VM and only on a folding volume; here the
 * fixtures are staged directly and the answers are inspected one component at a
 * time.
 *
 * The resolver reads the sysroot configuration through two functions from the
 * process-state layer, stubbed below so the test links the resolver and the
 * codec and nothing else.
 *
 * Code under test: src/syscall/casefold-walk.c. A regression shows up as a
 * wrong-case lookup that succeeds where Linux gives ENOENT, an escaped entry
 * that stops resolving, a create aimed at the wrong directory, or an over-long
 * path silently truncated to name a different file.
 *
 * Native macOS binary; no HVF entitlement needed.
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <unistd.h>

#include "host-test-util.h"

#include "syscall/casefold-walk.h"

/* Stubs for the process-state symbols the resolver reads. Only casefold_active
 * consults them, and the walk itself does not call it, so a fixed answer is
 * enough to link. Declared here rather than by including the process-state
 * header, which would pull the whole syscall layer in behind it.
 */
const char *proc_get_sysroot(void);
bool proc_sysroot_casefold_enabled(void);

static char stub_sysroot[PATH_MAX];
const char *proc_get_sysroot(void)
{
    return stub_sysroot[0] ? stub_sysroot : NULL;
}
bool proc_sysroot_casefold_enabled(void)
{
    return true;
}

static char root[PATH_MAX];
static bool volume_folds;

static void stage_file(const char *rel)
{
    char p[PATH_MAX];
    int fd;

    snprintf(p, sizeof(p), "%s/%s", root, rel);
    fd = open(p, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0)
        close(fd);
}

static void stage_dir(const char *rel)
{
    char p[PATH_MAX];

    snprintf(p, sizeof(p), "%s/%s", root, rel);
    mkdir(p, 0755);
}

/* Resolve @guest and compare the host spelling against @want_rel, which is
 * relative to the fixture root. @want_verdict is the expected outcome.
 */
static void check(const char *label,
                  const char *guest,
                  casefold_verdict_t want_verdict,
                  const char *want_rel)
{
    char out[LINUX_PATH_MAX];
    char want[PATH_MAX];
    casefold_walk_t walk;
    casefold_verdict_t got;

    got = casefold_resolve_at(AT_FDCWD, root, guest, false, out, sizeof(out),
                              &walk);
    if (got != want_verdict) {
        host_fail(label, "wrong verdict");
        fprintf(stderr, "  guest %s -> verdict %d, expected %d (host %s)\n",
                guest, (int) got, (int) want_verdict,
                got == CASEFOLD_ERROR ? strerror(errno) : out);
        return;
    }
    snprintf(want, sizeof(want), "%s%s%s", root, want_rel[0] ? "/" : "",
             want_rel);
    if (strcmp(out, want)) {
        host_fail(label, "wrong host spelling");
        fprintf(stderr, "  guest    %s\n  got      %s\n  expected %s\n", guest,
                out, want);
        return;
    }
    host_ok();
}

static void check_parent_found(const char *label, const char *guest, bool want)
{
    char out[LINUX_PATH_MAX];
    casefold_walk_t walk;

    if (casefold_resolve_at(AT_FDCWD, root, guest, false, out, sizeof(out),
                            &walk) == CASEFOLD_ERROR) {
        host_fail(label, strerror(errno));
        return;
    }
    if (walk.parent_found != want) {
        host_fail(label, want ? "parent should have been found"
                              : "parent should not have been found");
        return;
    }
    host_ok();
}

/* Names the codec escapes, spelled here so the expectations read literally. */
static const char *esc(const char *guest)
{
    static char buf[4][CASEFOLD_HOST_NAME_MAX + 1];
    static int slot;
    char *out = buf[slot++ % 4];

    if (casefold_escape(guest, out, CASEFOLD_HOST_NAME_MAX + 1) < 0)
        return "<escape failed>";
    return out;
}

static void section_literal(void)
{
    char want[PATH_MAX];

    /* A fold-stable name is stored as itself, so resolution is the identity
     * plus an existence answer.
     */
    check("lowercase file found", "/plain.txt", CASEFOLD_FOUND, "plain.txt");
    check("lowercase dir found", "/lowdir", CASEFOLD_FOUND, "lowdir");
    check("nested lowercase", "/lowdir/inner.txt", CASEFOLD_FOUND,
          "lowdir/inner.txt");
    check("absent lowercase", "/nothere", CASEFOLD_ABSENT, "nothere");

    /* A host-staged mixed-case name keeps its real spelling, which is what
     * makes an unpacked rootfs reachable, so the literal probe must find it
     * rather than reaching for the escape.
     */
    check("host-staged mixed case", "/Makefile", CASEFOLD_FOUND, "Makefile");
    check("host-staged mixed-case dir", "/Documentation", CASEFOLD_FOUND,
          "Documentation");
    check("nested under host-staged dir", "/Documentation/Guide.md",
          CASEFOLD_FOUND, "Documentation/Guide.md");

    /* The wrong case for a host-staged name is a Linux ENOENT. On a folding
     * volume the literal slot is occupied by a different spelling, so the name
     * resolves to its escape, which is absent, and the caller's own syscall
     * then reports ENOENT with no separate veto.
     */
    snprintf(want, sizeof(want), "%s",
             volume_folds ? esc("makefile") : "makefile");
    check("wrong case is absent", "/makefile", CASEFOLD_ABSENT, want);
}

static void section_escaped(void)
{
    char want[PATH_MAX];

    /* An escaped entry is found through its escape, and reported under the host
     * spelling the caller must actually use.
     */
    check("escaped file found", "/Guest.Made", CASEFOLD_FOUND,
          esc("Guest.Made"));
    check("escaped dir found", "/GuestDir", CASEFOLD_FOUND, esc("GuestDir"));
    snprintf(want, sizeof(want), "%s/deep.txt", esc("GuestDir"));
    check("nested below an escaped dir", "/GuestDir/deep.txt", CASEFOLD_FOUND,
          want);
}

static void section_absent(void)
{
    char want[PATH_MAX];

    /* Below an absent component nothing can be probed, and nothing needs to be:
     * the spelling of the rest follows from the names alone.
     */
    check("absent intermediate", "/nothere/child", CASEFOLD_ABSENT,
          "nothere/child");
    snprintf(want, sizeof(want), "nothere/%s", esc("Child"));
    check("absent intermediate, escaping tail", "/nothere/Child",
          CASEFOLD_ABSENT, want);

    check_parent_found("leaf absent, parent found", "/lowdir/missing", true);
    check_parent_found("intermediate absent", "/nothere/child", false);
    check_parent_found("existing leaf", "/plain.txt", true);

    /* A create below an existing escaped directory must land inside it. */
    snprintf(want, sizeof(want), "%s/%s", esc("GuestDir"), esc("New.File"));
    check("create below an escaped dir", "/GuestDir/New.File", CASEFOLD_ABSENT,
          want);
    snprintf(want, sizeof(want), "%s/new.file", esc("GuestDir"));
    check("fold-stable create below an escaped dir", "/GuestDir/new.file",
          CASEFOLD_ABSENT, want);
}

static void section_shapes(void)
{
    char want[PATH_MAX];

    /* An escape-shaped guest name is stored escaped, never probed literally, so
     * it cannot collide with the encoding of a different name.
     */
    snprintf(want, sizeof(want), "%s", esc(".ef=464f4f"));
    check("escape-shaped guest name", "/.ef=464f4f", CASEFOLD_ABSENT, want);

    /* Non-ASCII always escapes, whatever the script. */
    check("cjk name", "/\xe6\x96\x87\xe6\xa1\xa3.txt", CASEFOLD_ABSENT,
          esc("\xe6\x96\x87\xe6\xa1\xa3.txt"));

    /* Repeated and trailing separators name the same path. */
    check("redundant separators", "//lowdir///inner.txt", CASEFOLD_FOUND,
          "lowdir/inner.txt");
    check("empty path resolves the prefix", "", CASEFOLD_FOUND, "");
}

static void section_symlink(void)
{
    char out[LINUX_PATH_MAX];
    casefold_walk_t walk;

    /* A link the walk does not have to pass through is judged by its own name,
     * which is what nofollow on the final component means.
     */
    check("symlink resolved by its own name", "/link.to.lowdir", CASEFOLD_FOUND,
          "link.to.lowdir");

    /* A link the walk does have to pass through stops it, and the walk says so
     * rather than letting the host follow the stored bytes: those name a
     * guest path, whose components may be escaped and whose absolute form
     * starts at the sysroot, so the host would look somewhere else. The caller
     * resolves the target in the guest namespace and comes back.
     *
     * link_rest_offset points at what is left to resolve, and
     * link_guest_offset at the link itself, so a relative target can be joined
     * to the directory holding it.
     */
    if (casefold_resolve_at(AT_FDCWD, root, "/link.to.lowdir/inner.txt", false,
                            out, sizeof(out), &walk) == CASEFOLD_SYMLINK &&
        !strcmp(out + strlen(root), "/link.to.lowdir") &&
        !strcmp("/link.to.lowdir/inner.txt" + walk.link_rest_offset,
                "inner.txt") &&
        !strcmp("/link.to.lowdir/inner.txt" + walk.link_guest_offset,
                "link.to.lowdir/inner.txt"))
        host_ok();
    else
        host_fail("an intermediate link stops the walk",
                  "expected CASEFOLD_SYMLINK");

    /* A dangling link exists as a link. Asking about its target stops the walk
     * at the link too: whether the target is there is a question about a guest
     * path the caller has not resolved yet.
     */
    if (casefold_resolve_at(AT_FDCWD, root, "/dangling", false, out,
                            sizeof(out), &walk) == CASEFOLD_FOUND)
        host_ok();
    else
        host_fail("dangling link exists without following", "expected found");
    if (casefold_resolve_at(AT_FDCWD, root, "/dangling", true, out, sizeof(out),
                            &walk) == CASEFOLD_SYMLINK &&
        walk.link_rest_offset == strlen("/dangling"))
        host_ok();
    else
        host_fail("following a dangling link stops at the link",
                  "expected CASEFOLD_SYMLINK with nothing left to resolve");

    /* A second hard link to a symlink is that same link under another name,
     * and it resolves by the name the caller used. The volume reports the
     * primary link's name for such an entry, so a probe that trusts the
     * reported spelling alone rules it a fold and the walk reports absent,
     * which is how linkat(2) of a symlink produced an entry lstat could not
     * see.
     */
    check("fold-stable second link to a symlink", "/second-link",
          CASEFOLD_FOUND, "second-link");
    check("escaped second link to a symlink", "/Hard.Link", CASEFOLD_FOUND,
          esc("Hard.Link"));
}

static void section_limits(void)
{
    char guest[LINUX_PATH_MAX];
    char out[LINUX_PATH_MAX];
    casefold_walk_t walk;
    size_t len = 0;
    bool saw_toolong = false;
    int last_ok = 0;

    /* A guest may build a path several times longer than the host accepts, and
     * an escaped component roughly doubles it, so deep trees reach the host
     * limit first. Grow the path a component at a time and require the boundary
     * to be clean: every depth below it resolves and spells its last component
     * in full, and the first depth past it reports ENAMETOOLONG. Silent
     * truncation is the outcome that matters, because a truncated path names a
     * different file.
     */
    for (int depth = 1; depth <= 200; depth++) {
        char want_leaf[CASEFOLD_HOST_NAME_MAX + 1];
        char comp[64];
        int add;

        snprintf(comp, sizeof(comp), "DirectoryWithAnExcessivelyLongName%04d",
                 depth);
        add = snprintf(guest + len, sizeof(guest) - len, "/%s", comp);
        if (add < 0 || (size_t) add >= sizeof(guest) - len)
            break; /* the guest path itself reached Linux PATH_MAX */
        len += (size_t) add;

        if (casefold_resolve_at(AT_FDCWD, root, guest, false, out, sizeof(out),
                                &walk) == CASEFOLD_ERROR) {
            if (errno == ENAMETOOLONG)
                saw_toolong = true;
            else
                host_fail("deep path", strerror(errno));
            break;
        }
        if (casefold_escape(comp, want_leaf, sizeof(want_leaf)) < 0) {
            host_fail("deep path", "could not spell the expected leaf");
            break;
        }
        if (strcmp(out + walk.leaf_offset, want_leaf)) {
            host_fail("deep path", "last component was truncated");
            fprintf(stderr, "  depth %d, got %s\n", depth,
                    out + walk.leaf_offset);
            break;
        }
        last_ok = depth;
    }

    if (saw_toolong && last_ok > 0)
        host_ok();
    else
        host_fail("over-long host path", saw_toolong
                                             ? "no depth resolved at all"
                                             : "never reported ENAMETOOLONG");

    /* A caller buffer smaller than the prefix is the same class of failure. */
    char tiny[8];
    if (casefold_resolve_at(AT_FDCWD, root, "/plain.txt", false, tiny,
                            sizeof(tiny), &walk) == CASEFOLD_ERROR &&
        errno == ENAMETOOLONG)
        host_ok();
    else
        host_fail("caller buffer too small", "expected ENAMETOOLONG");
}

/* Forged getattrlist replies. No real volume produces these here, and
 * getattrlist(2) documents that a truncated reply can reference data beyond
 * the buffer, so the bounds check is exercised directly rather than through
 * the filesystem. Code under test: casefold_attr_stored_name(). A regression
 * dereferences the kernel-claimed offset unchecked and, on a volume that
 * misbehaves (an SMB or NFS --sysroot), reads past the probe's stack buffer.
 */
static void section_reply_bounds(void)
{
    struct {
        u_int32_t length;
        attribute_set_t returned;
        attrreference_t name_ref;
        fsobj_type_t obj_type;
        char name[32];
    } __attribute__((aligned(4), packed)) f;
    const size_t ref_off =
        (size_t) ((const char *) &f.name_ref - (const char *) &f);
    const int32_t name_off =
        (int32_t) ((const char *) f.name - (const char *) &f.name_ref);
    const char *got;

    memset(&f, 0, sizeof(f));
    f.length = sizeof(f);
    f.returned.commonattr =
        ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_OBJTYPE | ATTR_CMN_NAME;
    f.name_ref.attr_dataoffset = name_off;
    f.name_ref.attr_length = 6;
    memcpy(f.name, "hello", 6);

    got = casefold_attr_stored_name(&f, sizeof(f), ref_off);
    if (got && !strcmp(got, "hello"))
        host_ok();
    else
        host_fail("reply bounds", "well-formed reply rejected");

    f.name_ref.attr_dataoffset = -8;
    if (!casefold_attr_stored_name(&f, sizeof(f), ref_off))
        host_ok();
    else
        host_fail("reply bounds", "negative attr_dataoffset accepted");

    f.name_ref.attr_dataoffset = (int32_t) sizeof(f);
    if (!casefold_attr_stored_name(&f, sizeof(f), ref_off))
        host_ok();
    else
        host_fail("reply bounds", "attr_dataoffset past the reply accepted");

    f.name_ref.attr_dataoffset = name_off;
    f.name_ref.attr_length = 0;
    if (!casefold_attr_stored_name(&f, sizeof(f), ref_off))
        host_ok();
    else
        host_fail("reply bounds", "zero attr_length accepted");

    f.name_ref.attr_length = (u_int32_t) sizeof(f);
    if (!casefold_attr_stored_name(&f, sizeof(f), ref_off))
        host_ok();
    else
        host_fail("reply bounds", "attr_length past the reply accepted");

    /* The kernel claims fewer bytes than the reference needs: the documented
     * truncation shape, where the attribute data lies beyond what was copied.
     */
    f.name_ref.attr_length = 6;
    f.length = (u_int32_t) sizeof(u_int32_t);
    if (!casefold_attr_stored_name(&f, sizeof(f), ref_off))
        host_ok();
    else
        host_fail("reply bounds",
                  "reference beyond the claimed length accepted");

    /* A claimed length larger than the buffer must be capped at the buffer:
     * the kernel never writes more than attrBufSize, whatever length says.
     */
    f.length = (u_int32_t) sizeof(f) + 64;
    f.name_ref.attr_length = (u_int32_t) sizeof(f);
    if (!casefold_attr_stored_name(&f, sizeof(f), ref_off))
        host_ok();
    else
        host_fail("reply bounds", "claimed length past the buffer accepted");

    f.length = sizeof(f);
    f.name_ref.attr_length = 6;
    memset(f.name, 'x', sizeof(f.name));
    if (!casefold_attr_stored_name(&f, sizeof(f), ref_off))
        host_ok();
    else
        host_fail("reply bounds", "name without a terminator accepted");
}

/* Does this volume fold case? The resolver behaves the same either way from the
 * guest's point of view, but the host spelling it reports differs, so the
 * expectations have to know.
 */
static bool probe_folds(void)
{
    char a[PATH_MAX];
    char b[PATH_MAX];
    int fd;

    snprintf(a, sizeof(a), "%s/FoldProbe", root);
    snprintf(b, sizeof(b), "%s/foldprobe", root);
    fd = open(a, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0)
        close(fd);
    fd = open(b, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd >= 0) {
        close(fd);
        unlink(b);
        unlink(a);
        return false;
    }
    unlink(a);
    return true;
}

int main(int argc, char **argv)
{
    char host[CASEFOLD_HOST_NAME_MAX + 1];
    char p[PATH_MAX];

    if (host_scratch_root(argv[0], "elfuse-walk", argc > 1 ? argv[1] : NULL,
                          root, sizeof(root)) < 0)
        return 1;
    snprintf(stub_sysroot, sizeof(stub_sysroot), "%s", root);
    volume_folds = probe_folds();

    /* Host-staged fixtures keep their real spelling, exactly as a rootfs
     * unpacked from a tarball would.
     */
    stage_file("plain.txt");
    stage_dir("lowdir");
    stage_file("lowdir/inner.txt");
    stage_file("Makefile");
    stage_dir("Documentation");
    stage_file("Documentation/Guide.md");
    snprintf(p, sizeof(p), "%s/link.to.lowdir", root);
    if (symlink("lowdir", p) < 0 && errno != EEXIST)
        fprintf(stderr, "warning: symlink fixture failed: %s\n",
                strerror(errno));
    snprintf(p, sizeof(p), "%s/dangling", root);
    if (symlink("no-such-target", p) < 0 && errno != EEXIST)
        fprintf(stderr, "warning: dangling fixture failed: %s\n",
                strerror(errno));

    /* Second hard links to a symlink, one fold-stable and one escaped.
     * getattrlistat(ATTR_CMN_NAME) reports the primary link's name for these
     * (observed on APFS; a second link to a regular file reports itself), which
     * is the aliasing section_symlink pins the probe against. linkat without
     * AT_SYMLINK_FOLLOW so the link itself is linked, dangling target and all.
     */
    {
        char lp[PATH_MAX];

        snprintf(lp, sizeof(lp), "%s/second-link", root);
        if (linkat(AT_FDCWD, p, AT_FDCWD, lp, 0) < 0 && errno != EEXIST)
            fprintf(stderr, "warning: second-link fixture failed: %s\n",
                    strerror(errno));
        if (casefold_escape("Hard.Link", host, sizeof(host)) == 0) {
            snprintf(lp, sizeof(lp), "%s/%s", root, host);
            if (linkat(AT_FDCWD, p, AT_FDCWD, lp, 0) < 0 && errno != EEXIST)
                fprintf(stderr, "warning: escaped-link fixture failed: %s\n",
                        strerror(errno));
        }
    }

    /* Entries the guest would have created, staged under the spelling the
     * escape rule gives them.
     */
    if (casefold_escape("Guest.Made", host, sizeof(host)) == 0)
        stage_file(host);
    if (casefold_escape("GuestDir", host, sizeof(host)) == 0) {
        char rel[PATH_MAX];
        stage_dir(host);
        snprintf(rel, sizeof(rel), "%s/deep.txt", host);
        stage_file(rel);
    }

    section_literal();
    section_escaped();
    section_absent();
    section_shapes();
    section_symlink();
    section_limits();
    section_reply_bounds();

    remove_tree(root);
    return host_summary("test-casefold-walk-host");
}
