// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnpackAppliesWhiteoutsAcrossLayers(t *testing.T) {
	s, d := storeWithImage(t, "wh:1", testImage{layers: [][]tarEntry{
		{{Name: "a/"}, {Name: "a/keep", Body: "k"}, {Name: "a/gone", Body: "g"},
			{Name: "a/sub/"}, {Name: "a/sub/old", Body: "o"}, {Name: "a/dev", Body: "d"}},
		// A device replacing a lower file removes it; a hardlink to it in
		// a later layer must not abort the unpack.
		{{Name: "a/.wh.gone"}, {Name: "a/sub/.wh..wh..opq"}, {Name: "a/sub/new", Body: "n"},
			{Name: "a/dev", Type: tar.TypeChar, Major: 1}},
		{{Name: "a/devlink", Link: "a/dev", Type: tar.TypeLink}},
	}})
	dest := filepath.Join(t.TempDir(), "rootfs")
	var err error
	captureOutput(t, func() { err = unpackImageFresh(context.Background(), s, manifestOf(t, s, d), dest) })
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{
		"a/keep": true, "a/gone": false,
		"a/sub/old": false, "a/sub/new": true,
		"a/.wh.gone": false,
		"a/dev":      false, "a/.wh.dev": false, "a/devlink": false,
	} {
		_, err := os.Lstat(filepath.Join(dest, p))
		if want != (err == nil) {
			t.Errorf("%s: present=%v, want %v", p, err == nil, want)
		}
	}
	b, err := os.ReadFile(filepath.Join(dest, "a/sub/new"))
	if err != nil || string(b) != "n" {
		t.Fatalf("a/sub/new = %q, %v", b, err)
	}
}

func TestUnpackHardlinkSharesInode(t *testing.T) {
	s, d := storeWithImage(t, "hl:1", testImage{layers: [][]tarEntry{
		{{Name: "orig", Body: "x"}, {Name: "alias", Link: "orig", Type: 0x31}},
	}})
	dest := filepath.Join(t.TempDir(), "rootfs")
	if err := unpackImageFresh(context.Background(), s, manifestOf(t, s, d), dest); err != nil {
		t.Fatal(err)
	}
	a, err := os.Stat(filepath.Join(dest, "orig"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(dest, "alias"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Fatal("hardlink must share the inode")
	}
}

func TestUnpackFreshLeavesNothingOnFailure(t *testing.T) {
	s, d := storeWithImage(t, "bad:1", testImage{})
	// Corrupt the layer blob in place: the unpack must fail and remove its
	// staging tree.
	m := manifestOf(t, s, d)
	blob := filepath.Join(s.root, "blobs", "sha256", m.Layers[0].Digest.Hex())
	// The layout writes blobs read-only.
	if err := os.Chmod(blob, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blob, []byte("not gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	dest := filepath.Join(parent, "rootfs")
	if err := unpackImageFresh(context.Background(), s, m, dest); err == nil {
		t.Fatal("corrupt layer must fail the unpack")
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging leftovers: %v", entries)
	}
}

// A rename that loses to something other than a published directory is
// an error, not a concurrent winner.
func TestUnpackFreshRefusesNonDirectoryAtDest(t *testing.T) {
	s, d := storeWithImage(t, "occ:1", testImage{})
	m := manifestOf(t, s, d)
	parent := t.TempDir()
	dest := filepath.Join(parent, "rootfs")
	for _, plant := range []func() error{
		func() error { return os.WriteFile(dest, nil, 0o644) },
		func() error { return os.Symlink(t.TempDir(), dest) },
	} {
		if err := plant(); err != nil {
			t.Fatal(err)
		}
		if err := unpackImageFresh(context.Background(), s, m, dest); err == nil {
			t.Fatal("unpack over a non-directory dest must fail")
		}
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("staging leftovers: %v", entries)
		}
		os.Remove(dest)
	}
}

func TestStoreRootfsPublishedRefusals(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := storeRootfsPublished(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink refusal missing: %v", err)
	}
	file := filepath.Join(dir, "file")
	os.WriteFile(file, nil, 0o644)
	if _, err := storeRootfsPublished(file); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("non-dir refusal missing: %v", err)
	}
	ok, err := storeRootfsPublished(filepath.Join(dir, "absent"))
	if err != nil || ok {
		t.Fatalf("absent = %v, %v", ok, err)
	}
}

func TestCmdUnpackStoreCacheAndAlreadyUnpacked(t *testing.T) {
	s, d := storeWithImage(t, "cache:1", testImage{layers: [][]tarEntry{
		{{Name: "etc/"}, {Name: "etc/os-release", Body: "ID=fixture"}},
	}})
	var err error
	_, stderr := captureOutput(t, func() {
		err = cmdUnpack([]string{"--store", s.root, "cache:1"})
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, stderr, "Unpacking cache:1", "Unpacked cache:1")
	dest, _ := s.cacheDir(cacheRootfs, d)
	b, err := os.ReadFile(filepath.Join(dest, "etc/os-release"))
	if err != nil || string(b) != "ID=fixture" {
		t.Fatalf("cache content = %q, %v", b, err)
	}
	_, stderr = captureOutput(t, func() {
		err = cmdUnpack([]string{"--store", s.root, "cache:1"})
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, stderr, "Already unpacked")
}

func TestCmdUnpackExplicitRootfsMerges(t *testing.T) {
	s, _ := storeWithImage(t, "merge:1", testImage{layers: [][]tarEntry{
		{{Name: "fromimage", Body: "i"}},
	}})
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "user-file"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	var err error
	captureOutput(t, func() {
		err = cmdUnpack([]string{"--store", s.root, "--rootfs", dest, "merge:1"})
	})
	if err != nil {
		t.Fatal(err)
	}
	for f, want := range map[string]string{"user-file": "mine", "fromimage": "i"} {
		b, err := os.ReadFile(filepath.Join(dest, f))
		if err != nil || string(b) != want {
			t.Fatalf("%s = %q, %v", f, b, err)
		}
	}
}

func TestCacheDirRejectsOddDigests(t *testing.T) {
	s := tempStore(t)
	for _, bad := range []string{"sha512:" + strings.Repeat("a", 128), "sha256:short", "zzz",
		"sha256:" + strings.Repeat("g", 64)} {
		if _, err := s.cacheDir(cacheRootfs, bad); err == nil {
			t.Errorf("digest %q must be rejected", bad)
		}
	}
}

// The filter's header rewrites must be what Apply extracts: the device
// and its hardlink are absent, the symlink lands relative, and on
// darwin the setgid bit is gone.
func TestUnpackAppliesFilteredHeaders(t *testing.T) {
	s, d := storeWithImage(t, "filt:1", testImage{layers: [][]tarEntry{
		{{Name: "dev/"}, {Name: "dev/null", Type: tar.TypeChar, Major: 1},
			{Name: "dev/alias", Link: "dev/null", Type: tar.TypeLink},
			{Name: "bin/"}, {Name: "bin/busybox", Body: "x", Mode: 0o2755},
			{Name: "bin/sh", Link: "/bin/busybox"}},
	}})
	dest := filepath.Join(t.TempDir(), "rootfs")
	captureOutput(t, func() {
		if err := unpackImageFresh(context.Background(), s, manifestOf(t, s, d), dest); err != nil {
			t.Fatal(err)
		}
	})
	for _, absent := range []string{"dev/null", "dev/alias"} {
		if _, err := os.Lstat(filepath.Join(dest, absent)); err == nil {
			t.Errorf("%s: must not be extracted", absent)
		}
	}
	if target, err := os.Readlink(filepath.Join(dest, "bin/sh")); err != nil || target != "busybox" {
		t.Errorf("bin/sh -> %q, %v; want busybox", target, err)
	}
	fi, err := os.Stat(filepath.Join(dest, "bin/busybox"))
	if err != nil {
		t.Fatal(err)
	}
	if clearSpecialBits && fi.Mode()&os.ModeSetgid != 0 {
		t.Errorf("bin/busybox mode %v keeps setgid", fi.Mode())
	}
}

// An explicit --rootfs naming a non-directory is refused by name rather
// than handed to archive.Apply, which reports only an opaque root error.
func TestCmdUnpackExplicitRootfsRefusesNonDirectory(t *testing.T) {
	s, _ := storeWithImage(t, "demo:1", testImage{})
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, m, err := s.loadRef(context.Background(), "demo:1", defaultPlatform)
	if err != nil {
		t.Fatal(err)
	}
	err = unpackImage(context.Background(), s, "demo:1", m, file)
	if err == nil || !strings.Contains(err.Error(), "want a directory") {
		t.Fatalf("unpack into a regular file = %v, want a not-a-directory refusal", err)
	}
}

// A usr-merged layer records entries under a symlinked directory; the
// rewritten relative target must resolve where Apply lands the link.
func TestUnpackSymlinkUnderSymlinkedParentResolves(t *testing.T) {
	s, d := storeWithImage(t, "usrmerge:1", testImage{layers: [][]tarEntry{
		{{Name: "usr/"}, {Name: "usr/lib/"}, {Name: "usr/lib/foo", Body: "foo"},
			{Name: "lib", Link: "usr/lib"},
			{Name: "lib/bar", Link: "/usr/lib/foo"}},
	}})
	dest := filepath.Join(t.TempDir(), "rootfs")
	if err := unpackImageFresh(context.Background(), s, manifestOf(t, s, d), dest); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "usr", "lib", "bar"))
	if err != nil || string(b) != "foo" {
		t.Fatalf("usr/lib/bar = %q, %v; want it to resolve to foo", b, err)
	}
}

// A --rootfs spelled with a trailing separator stages beside the
// destination, not inside it.
func TestUnpackFreshAcceptsTrailingSeparator(t *testing.T) {
	s, d := storeWithImage(t, "slash:1", testImage{layers: [][]tarEntry{{{Name: "f", Body: "x"}}}})
	dest := filepath.Join(t.TempDir(), "out") + string(filepath.Separator)
	if err := unpackImageFresh(context.Background(), s, manifestOf(t, s, d), dest); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "f")); err != nil || string(b) != "x" {
		t.Fatalf("f = %q, %v; want the unpacked file", b, err)
	}
}
