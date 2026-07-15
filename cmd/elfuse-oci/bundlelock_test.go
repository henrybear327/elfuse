// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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

// TestSpawnElfuseWaitPassesLocksToChild pins the SIGKILL half of the
// case-sensitive path's liveness: the spawned guest must inherit the run
// lock's descriptor (ExtraFiles shares the open file description, exactly
// like exec inheritance), so a wrapper killed with an uncatchable signal
// leaves the flock held by the still-running guest and the sweeps keep
// seeing the bundle busy. The old behavior spawned the child without the
// descriptor: the lock died with the wrapper while the guest kept running,
// letting prune/rmi reclaim the tree under it.
func TestSpawnElfuseWaitPassesLocksToChild(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "run.lock")
	hold, err := acquireFlock(lockPath, syscall.LOCK_EX)
	if err != nil {
		t.Fatal(err)
	}
	lockHeld := func() bool {
		probe, err := acquireFlock(lockPath, syscall.LOCK_EX|syscall.LOCK_NB)
		if err != nil {
			if errors.Is(err, errCacheBusy) {
				return true
			}
			t.Fatal(err)
		}
		probe.Close()
		return false
	}

	// A fake elfuse that outlives the parent's fd close long enough for the
	// probe below.
	script := filepath.Join(dir, "fake-elfuse")
	if err := os.WriteFile(script,
		[]byte("#!/bin/sh\nexec /bin/sleep 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELFUSE_BIN", script)

	// The parent-side fd close below must happen after cmd.Start's reads of
	// the ExtraFiles descriptor; the child's own progress cannot order that
	// (a file touch is no happens-before edge), so take the edge from the
	// afterSpawnStart hook through a channel.
	started := make(chan struct{})
	oldHook := afterSpawnStart
	afterSpawnStart = func() { close(started) }
	t.Cleanup(func() { afterSpawnStart = oldHook })

	rootfs := t.TempDir()
	done := make(chan error, 1)
	go func() {
		_, err := spawnElfuseWait(rootfs, &runSpec{Args: []string{"/bin/true"}, Workdir: "/"}, hold)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("spawnElfuseWait never started the child")
	}

	// Close the wrapper's fd only (no LOCK_UN), modeling its uncatchable
	// death. The child's inherited descriptor must keep the flock held.
	if err := hold.f.Close(); err != nil {
		t.Fatal(err)
	}
	hold.f = nil
	if !lockHeld() {
		t.Error("lock not held by the child; a killed wrapper would free the bundle under the guest")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if lockHeld() {
		t.Error("lock still held after the child exited; the kernel should have released it")
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
