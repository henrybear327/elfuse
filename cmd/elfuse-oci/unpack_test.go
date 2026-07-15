// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func newRoot(t *testing.T) (*os.Root, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	return root, dir
}

func applyEntries(t *testing.T, root *os.Root, entries []tar.Header) {
	t.Helper()
	for _, h := range entries {
		var content []byte
		if (h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA) && h.Size > 0 {
			content = []byte(strings.Repeat("x", int(h.Size)))
		}
		hdr := h
		if err := applyEntry(root, &hdr, bytes.NewReader(content), map[string]bool{}); err != nil {
			t.Fatalf("applyEntry %q: %v", h.Name, err)
		}
	}
}

func applyEntryWithContent(t *testing.T, root *os.Root, h tar.Header, content string) {
	t.Helper()
	hdr := h
	hdr.Size = int64(len(content))
	if err := applyEntry(root, &hdr, strings.NewReader(content), map[string]bool{}); err != nil {
		t.Fatalf("applyEntry %q: %v", h.Name, err)
	}
}

func regHeader(name string, mode int64, size int64) tar.Header {
	return tar.Header{Name: name, Mode: mode, Typeflag: tar.TypeReg, Size: size}
}
func dirHeader(name string, mode int64) tar.Header {
	return tar.Header{Name: name, Mode: mode, Typeflag: tar.TypeDir}
}
func symHeader(name, target string) tar.Header {
	return tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target}
}
func linkHeader(name, target string) tar.Header {
	return tar.Header{Name: name, Typeflag: tar.TypeLink, Linkname: target}
}

func TestUnpackRegularFilePerm(t *testing.T) {
	root, dir := newRoot(t)
	applyEntryWithContent(t, root, regHeader("bin/prog", 0o755, 0), "")
	applyEntryWithContent(t, root, regHeader("etc/secret", 0o600, 0), "")

	fi, err := os.Stat(filepath.Join(dir, "bin", "prog"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("perm: got %o, want 755", fi.Mode().Perm())
	}
	fi, _ = os.Stat(filepath.Join(dir, "etc", "secret"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("perm: got %o, want 600", fi.Mode().Perm())
	}
}

func TestUnpackOldStyleRegularFile(t *testing.T) {
	root, dir := newRoot(t)
	applyEntryWithContent(t, root, tar.Header{
		Name:     "old-style",
		Mode:     0o644,
		Typeflag: tar.TypeRegA,
	}, "hello")

	got, err := os.ReadFile(filepath.Join(dir, "old-style"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("old-style file content = %q, want hello", got)
	}
}

func TestUnpackStickyAndSetuid(t *testing.T) {
	root, dir := newRoot(t)
	applyEntries(t, root, []tar.Header{
		dirHeader("tmp", 0o1777),
		regHeader("bin/su", 0o4755, 0),
	})

	fi, _ := os.Stat(filepath.Join(dir, "tmp"))
	if fi.Mode()&os.ModeSticky == 0 {
		t.Errorf("tmp missing sticky bit: %o", fi.Mode())
	}
	fi, _ = os.Stat(filepath.Join(dir, "bin", "su"))
	if fi.Mode()&os.ModeSetuid == 0 {
		t.Errorf("su missing setuid bit: %o", fi.Mode())
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("su perm: got %o, want 755", fi.Mode().Perm())
	}
}

// TestShouldDropSpecial pins the degrade decision applyMode makes when a
// mode-finalizing chmod fails: retry without the special bits only for a
// permission error that actually carried special bits, so a genuine chmod
// failure still surfaces. This is the portable stand-in for the live EPERM,
// which cannot be forced deterministically (t.TempDir() sits under a
// staff-group path where an unprivileged setgid chmod succeeds).
func TestShouldDropSpecial(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		special os.FileMode
		want    bool
	}{
		{"eperm with setgid degrades", syscall.EPERM, os.ModeSetgid, true},
		{"wrapped eperm with setuid degrades",
			&os.PathError{Op: "chmodat", Path: "usr/bin/su", Err: syscall.EPERM},
			os.ModeSetuid, true},
		{"eperm without special bits surfaces", syscall.EPERM, 0, false},
		{"non-permission error surfaces", syscall.EINVAL, os.ModeSetgid, false},
		{"success is not a degrade", nil, os.ModeSetgid, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldDropSpecial(tc.err, tc.special); got != tc.want {
				t.Errorf("shouldDropSpecial(%v, %o) = %v, want %v",
					tc.err, tc.special, got, tc.want)
			}
		})
	}
}

// TestUnpackSetgidForeignGroupDoesNotAbort pins that a setgid entry never
// aborts the unpack, even on a host that rejects the special-bit chmod (macOS,
// when the file's inherited group is one the invoking user is not in; see
// applyMode). The permission bits must always land; the setgid bit may or may
// not survive depending on the host group, so it is deliberately not asserted.
func TestUnpackSetgidForeignGroupDoesNotAbort(t *testing.T) {
	root, dir := newRoot(t)
	applyEntries(t, root, []tar.Header{
		dirHeader("usr", 0o755),
		dirHeader("usr/bin", 0o755),
		// chage in Debian: setgid group shadow, mode 02755.
		regHeader("usr/bin/chage", 0o2755, 0),
	})
	fi, err := os.Stat(filepath.Join(dir, "usr", "bin", "chage"))
	if err != nil {
		t.Fatalf("stat chage: %v", err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("chage perm: got %o, want 755", fi.Mode().Perm())
	}
}

// TestUnpackModesSurviveUmask pins that layer permissions are finalized with
// an explicit chmod: creation modes are masked by the process umask, so an
// image mode like 0755 or 0644 must survive a restrictive host umask even
// when no setuid/setgid/sticky bit is present. It also pins that a parent
// directory's exact mode from its own tar entry is not reset to the 0755
// default by the ensure-parent pass of a later child entry.
func TestUnpackModesSurviveUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	root, dir := newRoot(t)
	applyEntries(t, root, []tar.Header{
		dirHeader("opt", 0o755),
		regHeader("opt/tool", 0o755, 0),
		regHeader("opt/data", 0o644, 0),
		dirHeader("secret", 0o700),
		regHeader("secret/key", 0o600, 0),
	})

	for _, c := range []struct {
		name string
		want os.FileMode
	}{
		{"opt", 0o755},
		{"opt/tool", 0o755},
		{"opt/data", 0o644},
		{"secret", 0o700},
		{"secret/key", 0o600},
	} {
		fi, err := os.Stat(filepath.Join(dir, c.name))
		if err != nil {
			t.Fatalf("stat %s: %v", c.name, err)
		}
		if fi.Mode().Perm() != c.want {
			t.Errorf("%s perm: got %o, want %o", c.name, fi.Mode().Perm(), c.want)
		}
	}
}

func TestUnpackAbsoluteSymlinkRewritten(t *testing.T) {
	root, dir := newRoot(t)
	applyEntries(t, root, []tar.Header{
		dirHeader("bin", 0o755),
		regHeader("bin/busybox", 0o755, 0),
		// /bin/sh -> /bin/busybox (absolute). Should be rewritten to "busybox"
		// (relative), resolving to /bin/busybox under the sysroot.
		symHeader("bin/sh", "/bin/busybox"),
		// /lib/ld -> /lib/ld-musl.so.1
		dirHeader("lib", 0o755),
		regHeader("lib/ld-musl.so.1", 0o644, 0),
		symHeader("lib/ld", "/lib/ld-musl.so.1"),
	})

	got, err := os.Readlink(filepath.Join(dir, "bin", "sh"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(got) {
		t.Errorf("absolute symlink not rewritten: %q", got)
	}
	if got != "busybox" {
		t.Errorf("rewritten target: got %q, want busybox", got)
	}
	// Resolving the rewritten link must reach the real file.
	target := filepath.Join(dir, "bin", got)
	if _, err := os.Stat(target); err != nil {
		t.Errorf("rewritten link does not resolve: %v", err)
	}
	got2, _ := os.Readlink(filepath.Join(dir, "lib", "ld"))
	if filepath.IsAbs(got2) {
		t.Errorf("deep absolute symlink not rewritten: %q", got2)
	}
}

func TestUnpackAbsoluteSymlinkCleansRootTraversal(t *testing.T) {
	root, dir := newRoot(t)
	applyEntryWithContent(t, root, regHeader("escape", 0o644, 0), "")
	applyEntries(t, root, []tar.Header{
		dirHeader("usr", 0o755),
		dirHeader("usr/bin", 0o755),
		symHeader("usr/bin/link", "/../escape"),
	})

	link := filepath.Join(dir, "usr", "bin", "link")
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(link), got))
	want := filepath.Join(dir, "escape")
	if resolved != want {
		t.Errorf("rewritten target resolves to %s, want %s", resolved, want)
	}
}

func TestUnpackRelativeSymlinkPreserved(t *testing.T) {
	root, dir := newRoot(t)
	applyEntries(t, root, []tar.Header{
		dirHeader("lib", 0o755),
		regHeader("lib/real.so", 0o644, 0),
		symHeader("lib/link.so", "real.so"),
	})
	got, _ := os.Readlink(filepath.Join(dir, "lib", "link.so"))
	if got != "real.so" {
		t.Errorf("relative symlink changed: got %q, want real.so", got)
	}
}

func TestUnpackWhiteoutRemovesFile(t *testing.T) {
	root, dir := newRoot(t)
	applyEntries(t, root, []tar.Header{
		dirHeader("etc", 0o755),
		regHeader("etc/keep", 0o644, 0),
		regHeader("etc/gone", 0o644, 0),
		{Name: "etc/.wh.gone", Typeflag: tar.TypeReg},
	})
	if _, err := os.Stat(filepath.Join(dir, "etc", "gone")); !os.IsNotExist(err) {
		t.Errorf("whiteout did not remove etc/gone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "etc", "keep")); err != nil {
		t.Errorf("whiteout removed etc/keep: %v", err)
	}
}

func TestUnpackOpaqueClearsDirectory(t *testing.T) {
	root, dir := newRoot(t)
	applyEntries(t, root, []tar.Header{
		dirHeader("opt", 0o755),
		regHeader("opt/lower-a", 0o644, 0),
		regHeader("opt/lower-b", 0o644, 0),
		// Opaque marker clears opt, then this layer re-adds only lower-a.
		{Name: "opt/.wh..wh..opq", Typeflag: tar.TypeReg},
		regHeader("opt/lower-a", 0o644, 0),
	})
	if _, err := os.Stat(filepath.Join(dir, "opt", "lower-b")); !os.IsNotExist(err) {
		t.Errorf("opaque did not clear opt/lower-b: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "opt", "lower-a")); err != nil {
		t.Errorf("opaque removed re-added opt/lower-a: %v", err)
	}
}

func TestUnpackHardlink(t *testing.T) {
	root, dir := newRoot(t)
	applyEntryWithContent(t, root, regHeader("etc/passwd", 0o644, 5), "hello")
	applyEntries(t, root, []tar.Header{linkHeader("etc/passwd-link", "etc/passwd")})
	// Both must refer to the same inode (hardlink), same content.
	orig, err := os.Stat(filepath.Join(dir, "etc", "passwd"))
	if err != nil {
		t.Fatalf("hardlink source missing: %v", err)
	}
	link, err := os.Stat(filepath.Join(dir, "etc", "passwd-link"))
	if err != nil {
		t.Fatalf("hardlink target missing: %v", err)
	}
	if !os.SameFile(orig, link) {
		t.Fatal("passwd and passwd-link are distinct inodes, want a hardlink")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "etc", "passwd-link")); err != nil || string(b) != "hello" {
		t.Fatalf("hardlink content = %q, err=%v; want hello", b, err)
	}
}

func TestUnpackSpecialFilesRejected(t *testing.T) {
	cases := []struct {
		name     string
		typeflag byte
		want     string
	}{
		{"dev/ttyS0", tar.TypeChar, "char"},
		{"dev/sda", tar.TypeBlock, "block"},
		{"run/pipe", tar.TypeFifo, "fifo"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			root, dir := newRoot(t)
			hdr := tar.Header{Name: tc.name, Mode: 0o644, Typeflag: tc.typeflag}
			err := applyEntry(root, &hdr, strings.NewReader(""), map[string]bool{})
			if err == nil || !strings.Contains(err.Error(), "unsupported special file type "+tc.want) {
				t.Fatalf("applyEntry special %s err = %v, want unsupported error", tc.want, err)
			}
			if _, err := os.Lstat(filepath.Join(dir, tc.name)); !os.IsNotExist(err) {
				t.Fatalf("special entry %s on disk: %v, want IsNotExist", tc.name, err)
			}
		})
	}
}

func TestUnpackPathEscapeRejected(t *testing.T) {
	root, _ := newRoot(t)
	hdr := regHeader("../escape", 0o644, 0)
	if err := applyEntry(root, &hdr, strings.NewReader(""), map[string]bool{}); err == nil {
		t.Fatalf("applyEntry accepted ../escape path")
	}
}

func TestUnpackWritesFileContent(t *testing.T) {
	root, dir := newRoot(t)
	applyEntryWithContent(t, root, regHeader("msg.txt", 0o644, 5), "hello")
	b, err := os.ReadFile(filepath.Join(dir, "msg.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Errorf("content: got %q, want hello", b)
	}
}

// Ensure applyEntry reads exactly the header's Size bytes from the reader
// (no over-read, no short read). The reader carries trailing bytes beyond
// Size so an over-read would be visible in both the count and the content,
// and a too-small reader must fail rather than write a truncated file.
func TestUnpackReadsExactSize(t *testing.T) {
	root, dir := newRoot(t)
	content := "abc123"
	r := &countingReader{b: []byte(content + "TRAILING-JUNK")}
	hdr := regHeader("f", 0o644, int64(len(content)))
	if err := applyEntry(root, &hdr, r, map[string]bool{}); err != nil {
		t.Fatalf("applyEntry: %v", err)
	}
	if r.n != len(content) {
		t.Errorf("bytes read: got %d, want %d", r.n, len(content))
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "f")); string(b) != content {
		t.Errorf("content mismatch: got %q", b)
	}

	short := &countingReader{b: []byte("abc")}
	hdr = regHeader("g", 0o644, int64(len(content)))
	if err := applyEntry(root, &hdr, short, map[string]bool{}); err == nil {
		t.Fatal("applyEntry accepted a short body, want size-mismatch error")
	}
}

type countingReader struct {
	b []byte
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.n >= len(c.b) {
		return 0, io.EOF
	}
	n := copy(p, c.b[c.n:])
	c.n += n
	return n, nil
}

// TestUnpackAbsoluteMemberNames pins the root-relative application of member
// names archived absolute (GNU tar -P builders): "/etc/foo" must land at
// <rootfs>/etc/foo instead of every os.Root operation rejecting the name
// with "path escapes from parent".
func TestUnpackAbsoluteMemberNames(t *testing.T) {
	root, dir := newRoot(t)
	applyEntries(t, root, []tar.Header{
		dirHeader("/etc", 0o755),
		regHeader("/etc/foo", 0o644, 5),
	})
	b, err := os.ReadFile(filepath.Join(dir, "etc", "foo"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "xxxxx" {
		t.Errorf("content = %q, want xxxxx", b)
	}
}

// TestUnpackAbsoluteHardlinkTarget pins root-relative hard-link targets: a
// layer entry "bin/sh" hardlinked to "/bin/busybox" (absolute Linkname, legal
// in OCI layers) must link to the rootfs's own busybox, not abort the unpack
// with os.Root's "path escapes from parent".
func TestUnpackAbsoluteHardlinkTarget(t *testing.T) {
	root, dir := newRoot(t)
	applyEntryWithContent(t, root, regHeader("bin/busybox", 0o755, 0), "hello")
	applyEntries(t, root, []tar.Header{
		linkHeader("bin/sh", "/bin/busybox"),
	})
	a, err := os.Stat(filepath.Join(dir, "bin", "busybox"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(dir, "bin", "sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Error("bin/sh is not a hard link to bin/busybox")
	}
}
