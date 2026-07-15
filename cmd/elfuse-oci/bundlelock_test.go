// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAcquireFlockSharedCoexists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")
	a, err := acquireFlock(path, syscall.LOCK_SH)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := acquireFlock(path, syscall.LOCK_SH|syscall.LOCK_NB)
	if err != nil {
		t.Fatalf("second shared lock: %v, want success", err)
	}
	defer b.Close()
}

func TestAcquireFlockExclusiveBlockedIsCacheBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")
	a, err := acquireFlock(path, syscall.LOCK_SH)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, err = acquireFlock(path, syscall.LOCK_EX|syscall.LOCK_NB)
	if !errors.Is(err, errCacheBusy) {
		t.Fatalf("exclusive over shared err = %v, want errCacheBusy", err)
	}

	// Releasing the shared lock frees the exclusive probe.
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := acquireFlock(path, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		t.Fatalf("exclusive after release: %v, want success", err)
	}
	defer b.Close()
}

func TestFlockDowngradeAdmitsSharedBlocksExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")
	a, err := acquireFlock(path, syscall.LOCK_EX)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := acquireFlock(path, syscall.LOCK_SH|syscall.LOCK_NB); !errors.Is(err, errCacheBusy) {
		t.Fatalf("shared over exclusive err = %v, want errCacheBusy", err)
	}
	if err := a.Downgrade(); err != nil {
		t.Fatalf("Downgrade: %v", err)
	}
	b, err := acquireFlock(path, syscall.LOCK_SH|syscall.LOCK_NB)
	if err != nil {
		t.Fatalf("shared after downgrade: %v, want success", err)
	}
	defer b.Close()
	if _, err := acquireFlock(path, syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, errCacheBusy) {
		t.Fatalf("exclusive after downgrade err = %v, want errCacheBusy", err)
	}
}

// TestAcquireFlockUnlinkRace pins the verify-retry: when a sweeper unlinks
// the lock file while another process still holds a lock on the orphaned
// inode, a fresh acquire must land on the recreated file, not block on or
// share fate with the orphan.
func TestAcquireFlockUnlinkRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")
	orphan, err := acquireFlock(path, syscall.LOCK_EX)
	if err != nil {
		t.Fatal(err)
	}
	defer orphan.Close()
	// Simulate the sweeper's RemoveAll of the bundle: the path is gone while
	// the orphan's lock is still held on the old inode.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	fresh, err := acquireFlock(path, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		t.Fatalf("acquire after unlink: %v, want success on recreated file", err)
	}
	defer fresh.Close()
}

func TestFlockCloseIdempotentAndNilSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")
	a, err := acquireFlock(path, syscall.LOCK_EX)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second Close: %v, want nil", err)
	}
	var nilLock *flockFile
	if err := nilLock.Close(); err != nil {
		t.Fatalf("nil Close: %v, want nil", err)
	}
}

func TestBundleLockPaths(t *testing.T) {
	if got := attachLockPath("/store/cs/sha256/ab"); got != "/store/cs/sha256/ab/attach.lock" {
		t.Fatalf("attachLockPath = %q", got)
	}
	if got := runLockPath("/store/cs/sha256/ab"); got != "/store/cs/sha256/ab/run.lock" {
		t.Fatalf("runLockPath = %q", got)
	}
}

// TestAcquireAttachLockRecreatesSweptBundleDir pins the provision-vs-sweep
// race recovery: when a prune --cache --all removed the whole bundle dir
// after provision's MkdirAll, the attach.lock open fails with ENOENT on the
// vanished parent. acquireAttachLock must recreate the dir and take the lock
// so the run re-provisions instead of failing.
func TestAcquireAttachLockRecreatesSweptBundleDir(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "sha256-deadbeef")
	// The dir is deliberately never created: this is the post-sweep state.
	lock, err := acquireAttachLock(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := os.Stat(attachLockPath(bundle)); err != nil {
		t.Fatalf("attach.lock not recreated in swept bundle dir: %v", err)
	}
}
