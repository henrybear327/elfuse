// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
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

// TestPreserveAcrossExecClearsCloexec pins the exec-survival half of the
// plain-rootfs run lock: Go opens files close-on-exec, so without the
// FD_SETFD clear the flock would silently drop at syscall.Exec.
func TestPreserveAcrossExecClearsCloexec(t *testing.T) {
	l, err := acquireFlock(filepath.Join(t.TempDir(), "x.lock"), syscall.LOCK_SH)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	flags, err := unix.FcntlInt(l.f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("lock fd unexpectedly not close-on-exec before PreserveAcrossExec")
	}
	if err := l.PreserveAcrossExec(); err != nil {
		t.Fatal(err)
	}
	flags, err = unix.FcntlInt(l.f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC != 0 {
		t.Fatal("FD_CLOEXEC still set after PreserveAcrossExec")
	}
}

// TestRootfsLockSurvivesIntoChildProcess models the exec handoff with the
// closest testable analog: hand the lock's descriptor to a child via
// ExtraFiles (a dup shares the open file description, exactly like exec
// inheritance), drop the parent's fd WITHOUT unlocking, and require the
// flock to live precisely as long as the child: released by the kernel at
// kill, no unlock code run. An in-process syscall.Exec is untestable by
// construction; this pins the same kernel behavior the run path relies on.
func TestRootfsLockSurvivesIntoChildProcess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	hold, err := acquireRootfsRunLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("/bin/sleep", "30")
	child.ExtraFiles = []*os.File{hold.f}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	// Close the parent's fd only (no LOCK_UN), mirroring the process image
	// being replaced. The child's dup keeps the description locked.
	if err := hold.f.Close(); err != nil {
		t.Fatal(err)
	}
	hold.f = nil

	if !rootfsCacheBusy(dir) {
		t.Error("lock not held while child lives; exec inheritance would drop it")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	if rootfsCacheBusy(dir) {
		t.Error("lock still held after child death; kernel should have released it")
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
