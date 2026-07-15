// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The darwin-only sparsebundle lifecycle (prune --cache detaching a stale mount
// and reaping abandoned COW clones, rmi --force dropping a mounted bundle)
// cannot run in hosted CI: it needs hdiutil + APFS + a real attach. The
// cross-platform pieces it rests on (listSweepableClones, csBundleBusy, the
// bundle flocks, pruneCaches, pruneRootfsCaches) are covered in
// lifecycle_test.go and bundlelock_test.go. This file adds the darwin-only
// round-trip behind ELFUSE_OCI_DARWIN_CS=1 so a Mac operator can opt in;
// without the flag it skips, so `go test ./cmd/elfuse-oci/` stays green
// everywhere by default.

// TestDarwinCSSweep exercises the crash-recovery path prune --cache runs per
// sparsebundle bundle: while a live run holds the bundle's run.lock the volume
// is reported busy and stays attached; once that run is gone the next sweep
// reaps the abandoned (unmarked) clone, preserves a --keep-marked clone, and
// detaches, after which removeRefCaches drops the whole bundle. Gated because
// it provisions a real APFS sparsebundle via hdiutil.
func TestDarwinCSSweep(t *testing.T) {
	if os.Getenv("ELFUSE_OCI_DARWIN_CS") == "" {
		t.Skip("set ELFUSE_OCI_DARWIN_CS=1 to exercise the darwin sparsebundle sweep (needs hdiutil + APFS)")
	}

	s := openTestStore(t)
	digest := "sha256:" + strings.Repeat("1", 64)
	bundle, err := csBundleDirForDigest(s.root, digest)
	if err != nil {
		t.Fatal(err)
	}
	mnt := filepath.Join(bundle, "mnt")
	// provision returns a mount holding run.lock shared; this stands in for
	// the live run. Drop owned so Close does not detach; we release the
	// liveness lock explicitly to simulate the run exiting.
	m, err := provisionCaseSensitive(bundle, mnt, "32m")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	m.owned = false
	t.Cleanup(func() {
		if isMountPoint(mnt) {
			_ = detachForce(mnt)
		}
	})

	// Plant an abandoned clone (reapable) and a --keep-marked clone (preserved).
	reapClone := filepath.Join(mnt, "run-1-1")
	keepClone := filepath.Join(mnt, "run-2-2")
	for _, p := range []string{reapClone, keepClone} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeKeepMarker(keepClone); err != nil {
		t.Fatal(err)
	}
	if !isMountPoint(mnt) {
		t.Fatalf("mnt %s not attached after provision", mnt)
	}

	// First sweep: the live run still holds run.lock, so the bundle is busy;
	// nothing is reaped and the volume stays attached.
	reaped, busy, unlock, err := sweepCSBundle(bundle)
	if err != nil {
		t.Fatalf("sweepCSBundle: %v", err)
	}
	unlock()
	if !busy {
		t.Fatal("sweepCSBundle busy = false while a live run holds run.lock")
	}
	if len(reaped) != 0 {
		t.Fatalf("sweepCSBundle reaped = %v while busy, want none", reaped)
	}
	if !isMountPoint(mnt) {
		t.Fatal("volume detached although a live run remains")
	}

	// The live run exits: release its run.lock.
	if err := m.runLock.Close(); err != nil {
		t.Fatal(err)
	}

	// Second sweep, idle now: the unmarked clone is reaped, the kept clone
	// preserved, and the stale mount detached.
	reaped, busy, unlock, err = sweepCSBundle(bundle)
	if err != nil {
		t.Fatalf("sweepCSBundle after run exit: %v", err)
	}
	unlock()
	if busy {
		t.Fatalf("second sweep reported busy, want idle")
	}
	if len(reaped) != 1 || reaped[0] != reapClone {
		t.Fatalf("second sweep reaped = %v, want [%s]", reaped, reapClone)
	}
	if isMountPoint(mnt) {
		t.Errorf("mnt still attached after idle sweepCSBundle, want detached")
	}

	// removeRefCaches should now delete the whole bundle directory, kept clone
	// and all.
	if err := removeRefCaches(s, digest); err != nil {
		t.Fatalf("removeRefCaches: %v", err)
	}
	if _, err := os.Stat(bundle); !os.IsNotExist(err) {
		t.Errorf("bundle dir after removeRefCaches: %v, want IsNotExist", err)
	}
}
