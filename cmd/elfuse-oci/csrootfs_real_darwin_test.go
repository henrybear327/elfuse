// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The real hdiutil round trip: create, attach, case-colliding names
// coexist, Clonefile, detach. Gated on real disk arbitration.
func TestDarwinCSRealHdiutil(t *testing.T) {
	if os.Getenv("ELFUSE_OCI_DARWIN_CS") == "" {
		t.Skip("set ELFUSE_OCI_DARWIN_CS=1 to run the real hdiutil round-trip")
	}
	bundle := filepath.Join(t.TempDir(), "bundle")
	mount, err := provisionCaseSensitive(bundle, "1g")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = detachForce(mount) })
	if !isMountPoint(mount) {
		t.Fatalf("%s is not a mount point after attach", mount)
	}

	// Case sensitivity is the volume's reason to exist.
	for _, name := range []string{"Foo", "foo"} {
		if err := os.WriteFile(filepath.Join(mount, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(mount)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}
	if !names["Foo"] || !names["foo"] {
		t.Fatalf("case-colliding names did not coexist: %v", names)
	}

	// A COW clone inside the volume, as runCaseSensitive makes per run.
	base := filepath.Join(mount, "rootfs")
	if err := os.MkdirAll(filepath.Join(base, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "bin", "app"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(mount, "run-clone")
	if err := unix.Clonefile(base, clone, unix.CLONE_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(clone, "bin", "app"))
	if err != nil || string(b) != "x" {
		t.Fatalf("clone content = %q, %v", b, err)
	}

	if err := detachForce(mount); err != nil {
		t.Fatal(err)
	}
	if isMountPoint(mount) {
		t.Fatal("still mounted after detach")
	}
}
