// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The exact flag spellings elfuse receives, and the "--" separator.
func TestElfuseArgvShape(t *testing.T) {
	spec := &runSpec{
		Args:    []string{"-evil", "arg"},
		Env:     []string{"A=1", "B=2"},
		Workdir: "/work",
		UID:     1000,
		GID:     7,
	}
	got := elfuseArgv("/rf", spec)
	want := []string{"elfuse", "--sysroot", "/rf", "--user", "1000:7",
		"--workdir", "/work", "--clear-env", "--env", "A=1", "--env", "B=2",
		"--", "-evil", "arg"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv:\n got %q\nwant %q", got, want)
	}
}

// $ELFUSE_BIN wins, and a missing binary yields the hint rather than a
// bare ENOENT that reads as an image problem.
func TestResolveElfuseBinEnvAndMissing(t *testing.T) {
	want := filepath.Join(t.TempDir(), "elfuse-custom")
	if err := os.WriteFile(want, []byte("#!"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELFUSE_BIN", want)
	got, err := resolveElfuseBin()
	if err != nil || got != want {
		t.Fatalf("resolveElfuseBin with env = %q, %v", got, err)
	}

	t.Setenv("ELFUSE_BIN", filepath.Join(t.TempDir(), "absent"))
	if _, err := resolveElfuseBin(); err == nil || !strings.Contains(err.Error(), "ELFUSE_BIN") {
		t.Fatalf("missing binary err = %v, want not-found with hint", err)
	}
}

// A failed exec returns instead of replacing the process, naming the
// binary.
func TestExecElfuseFailureReturns(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "missing-elfuse")
	err := execElfuse(bin, t.TempDir(), &runSpec{Args: []string{"/bin/true"}, Workdir: "/"})
	if err == nil || !strings.Contains(err.Error(), "exec "+bin) {
		t.Fatalf("err = %v, want exec failure", err)
	}
}

func TestInsideStore(t *testing.T) {
	store := t.TempDir()
	for path, want := range map[string]bool{
		filepath.Join(store, "rootfs", "sha256", "aa"):       true,
		filepath.Join(store, "cs", "sha256", "aa"):           true,
		filepath.Join(strings.ToUpper(store), "ROOTFS", "x"): true,
		filepath.Join(store, "blobs"):                        true,
		store:                                                true,
		store + "-sibling":                                   false,
		t.TempDir():                                          false,
	} {
		if got := insideStore(store, path); got != want {
			t.Errorf("insideStore(%q) = %v, want %v", path, got, want)
		}
	}
	// A symlink into the store must not bypass the refusal.
	inside := filepath.Join(store, "rootfs", "sha256", "bb")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	if !insideStore(store, link) {
		t.Fatal("symlinked spelling must still read as inside the store")
	}
	// The leaf need not exist yet: --rootfs names a directory to create,
	// and its symlinked parent must not bypass the refusal either.
	if !insideStore(store, filepath.Join(link, "not-yet")) {
		t.Fatal("a missing leaf under a symlinked parent must still read as inside the store")
	}
}

// writeElfuseStub installs a shell stub as $ELFUSE_BIN so launch tests
// need no real elfuse and no HVF.
func writeElfuseStub(t *testing.T, body string) string {
	t.Helper()
	p := writeShellStub(t, "elfuse-stub.sh", body)
	t.Setenv("ELFUSE_BIN", p)
	return p
}

// An existing --rootfs that is not a directory is refused by name before
// anything is written into it: os.OpenRoot would follow a symlink out
// of the tree the user named.
func TestRunPlainRootfsRefusesNonDirectory(t *testing.T) {
	s, d := storeWithImage(t, "pl:1", testImage{})
	m := manifestOf(t, s, d)
	_, cfg, err := s.configFor(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o644)
	for _, rootfs := range []string{link, file} {
		rc := &runContext{s: s, ref: "pl:1", digest: d, m: m, cfg: cfg, rf: runFlags{rootfs: rootfs}}
		err := runPlainRootfs(context.Background(), rc)
		if err == nil || !strings.Contains(err.Error(), "want a directory") {
			t.Errorf("rootfs %s: err = %v, want a not-a-directory refusal", rootfs, err)
		}
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("symlink target was written into: %v", entries)
	}
}
