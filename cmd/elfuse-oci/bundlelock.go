// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Per-digest bundle locks.
//
// A case-sensitive sparsebundle bundle (<store>/cs/<algo>/<hex>/) is shared
// mutable state: concurrent `run`s of one digest share its attached volume,
// while prune --cache and rmi --force want to detach and remove it. Liveness
// is decided by advisory flocks, not by pids or directory scans: a held
// lock proves a live holder regardless of pid reuse, and a free lock proves
// the holder is gone regardless of what the directory contains.
//
// Two lock files live in the bundle directory, deliberately OUTSIDE the
// mounted volume: hdiutil detach -force revokes descriptors inside the
// volume, which would silently drop a lock held there, and the locks must be
// probeable while the volume is not attached at all.
//
//   - attach.lock: exclusive, serializes bundle lifecycle transitions. A run
//     holds it (blocking) across provisioning (stale-mount recovery,
//     hdiutil create/attach) and the last-one-out detach; a sweep holds it
//     (non-blocking) for its whole reap-detach-remove sequence.
//   - run.lock: every live run holds it shared from before the volume is
//     attached until the guest exits (the process exiting releases it, so a
//     killed run cannot leak liveness). Anyone holding it exclusively has
//     proven there are zero live runs: sweeps take it non-blocking (busy =>
//     skip the bundle), and provision probes it to tell a stale leftover
//     mount from one that is live.
//
// Lock ordering: attach.lock is always acquired before run.lock is taken
// exclusively. That makes the EX->SH downgrade in provision safe (flock
// downgrades by release-and-reacquire, but no EX taker can slip in without
// attach.lock, which the downgrader holds) and rules out lock-order cycles
// with the store-level .lock, which prune/rmi already hold around the sweep
// while runs never take bundle locks under the store lock.

// errCacheBusy reports that a bundle lock is held by a live run (or an
// in-flight provision), so the caller must not detach or remove the bundle.
var errCacheBusy = errors.New("in use by a live run")

func attachLockPath(bundle string) string { return filepath.Join(bundle, "attach.lock") }
func runLockPath(bundle string) string    { return filepath.Join(bundle, "run.lock") }

// flockFile is an open file holding (or having held) an advisory flock.
type flockFile struct {
	f *os.File
}

// acquireFlock opens path (creating it if absent) and takes the flock mode
// `how` (syscall.LOCK_SH or LOCK_EX, optionally |LOCK_NB). A non-blocking
// request that loses returns errCacheBusy (wrapped with the path).
//
// A sweeper removes the whole bundle directory, lock files included,
// while holding both locks. A racing acquirer may then have opened the path
// just before the unlink and be holding a lock on an orphaned inode no later
// process can observe. Guard against that: after locking, verify the path
// still resolves to the locked inode; otherwise retry against the recreated
// file. The retry count is a defense bound, not a correctness knob; one
// retry per concurrent unlink is the worst case.
func acquireFlock(path string, how int) (*flockFile, error) {
	for range 16 {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			return nil, err
		}
		if err := flockRetryIntr(int(f.Fd()), how); err != nil {
			f.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
				return nil, fmt.Errorf("%s: %w", path, errCacheBusy)
			}
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		var pathSt, fdSt syscall.Stat_t
		if err := syscall.Stat(path, &pathSt); err != nil {
			f.Close()
			if errors.Is(err, syscall.ENOENT) {
				continue // unlinked under us; retry on the recreated file
			}
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if err := syscall.Fstat(int(f.Fd()), &fdSt); err != nil {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if pathSt.Dev == fdSt.Dev && pathSt.Ino == fdSt.Ino {
			return &flockFile{f: f}, nil
		}
		f.Close() // path now names a different file; lock that one instead
	}
	return nil, fmt.Errorf("lock %s: persistent unlink race", path)
}

// flockRetryIntr issues flock, retrying on EINTR (a blocking acquisition may
// be interrupted by the signal forwarding the run wrapper installs).
func flockRetryIntr(fd, how int) error {
	for {
		err := syscall.Flock(fd, how)
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

// Downgrade converts a held exclusive lock to shared. flock implements this
// as release-then-reacquire, so it is race-free only while the caller holds
// attach.lock: every exclusive taker of run.lock acquires attach.lock first,
// so none can slip into the gap.
func (l *flockFile) Downgrade() error {
	return flockRetryIntr(int(l.f.Fd()), syscall.LOCK_SH)
}

// Close releases the lock and closes the file. Safe on nil and after a prior
// Close.
func (l *flockFile) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	err := l.f.Close()
	l.f = nil
	return err
}

// acquireAttachLock takes the exclusive attach.lock for bundleDir, recreating
// the directory when a concurrent sweep removed it. A prune --cache --all can
// win both bundle locks and RemoveAll the whole bundle dir (lock files
// included) while a provisioning run is blocked on attach.lock; that run then
// wakes on the orphaned lock inode, retries, and finds the open of the lock
// path failing with ENOENT on the vanished parent. Recreating the dir and
// retrying lets the run re-provision the swept bundle from scratch instead of
// failing; a few tries bound the pathological case of back-to-back sweeps.
func acquireAttachLock(bundleDir string) (*flockFile, error) {
	lock, err := acquireFlock(attachLockPath(bundleDir), syscall.LOCK_EX)
	for tries := 0; errors.Is(err, syscall.ENOENT) && tries < 4; tries++ {
		if mkErr := os.MkdirAll(bundleDir, 0o755); mkErr != nil {
			return nil, mkErr
		}
		lock, err = acquireFlock(attachLockPath(bundleDir), syscall.LOCK_EX)
	}
	return lock, err
}
