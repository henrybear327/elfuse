// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Per-digest plain-rootfs cache locks.
//
// The plain digest-keyed rootfs cache (<store>/rootfs/<algo>/<hex>/) is the
// same kind of shared mutable state as a sparsebundle bundle: a
// --plain-rootfs run executes a guest out of it while prune --cache and rmi
// want to RemoveAll it. Liveness follows the bundlelock.go discipline (a
// held flock proves a live holder regardless of pids) with one lock
// instead of two: there is no mount lifecycle to serialize (no attach.lock
// analog), and concurrent cold unpacks already reconcile through
// unpackImage's stage-and-rename.
//
// The lock is a SIBLING file (<hex>.lock next to the cache dir), not a file
// inside it: the cache dir is the guest's /, so a lock inside would appear
// at the guest's / in every run, and the dir's very existence is the
// "fully unpacked" signal that unpackImage publishes by atomic rename.
// Prune's sweep enumerations skip non-directories, so the lock file is
// invisible to them.
//
//   - A run (and a store-cache unpack) holds the lock SHARED from before the
//     cache-existence probe until the guest exits. The plain run path execs
//     elfuse in place, so PreserveAcrossExec threads the descriptor through
//     the exec: the kernel releases the flock exactly when the elfuse
//     process exits, SIGKILL included, the same no-leaked-liveness property
//     run.lock gives the sparsebundle path.
//   - prune --cache takes it EXCLUSIVE non-blocking and skips a busy cache;
//     rmi refuses a busy cache outright. The remover deletes the lock file
//     while still holding the lock; acquireFlock's stat-after-lock guard
//     already handles a racing acquirer.
//
// Ordering stays acyclic: runs take the rootfs lock while holding no store
// lock, and prune/rmi (which do hold the store lock) only ever probe the
// rootfs lock non-blocking.

func rootfsRunLockPath(dir string) string { return dir + ".lock" }

// rootfsCacheLockPath returns the lock file guarding a cache dir in the
// prune sweep. A published cache <hex> is guarded by its sibling <hex>.lock.
// A staging dir <hex>.tmp-<random> (unpackImage's pre-rename workspace, a
// temp sibling in the same parent) is guarded by the SAME <hex>.lock: the
// unpacker holds that lock from before the cache-existence probe until the
// guest exits, so a probe on a lock named after the staging dir itself
// proves nothing and would let the sweep reclaim a tree a live unpack is
// still writing. A staging dir whose digest lock is free is a crashed
// unpack's leftover and remains reclaimable.
func rootfsCacheLockPath(dir string) string {
	if hex, _, isStaging := strings.Cut(filepath.Base(dir), rootfsStagingSuffix); isStaging {
		return rootfsRunLockPath(filepath.Join(filepath.Dir(dir), hex))
	}
	return rootfsRunLockPath(dir)
}

// acquireRootfsRunLock takes dir's run lock shared, blocking: if a prune is
// mid-removal the run waits it out and then re-unpacks the reclaimed cache.
// The parent directory is created first so a cold store can take the lock
// before its first unpack.
func acquireRootfsRunLock(dir string) (*flockFile, error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return nil, err
	}
	return acquireFlock(rootfsRunLockPath(dir), syscall.LOCK_SH)
}

// rootfsCacheBusy reports whether a live run holds dir's run lock. Used by
// prune's dry-run so it never advertises a reap the real pass would refuse.
// A missing lock file means no holder (holders create it), so the probe
// creates no state; any other failure fails closed to busy.
func rootfsCacheBusy(dir string) bool {
	f, err := os.OpenFile(rootfsCacheLockPath(dir), os.O_RDWR, 0)
	if err != nil {
		return !os.IsNotExist(err)
	}
	defer f.Close()
	if err := flockRetryIntr(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}

// lockRootfsCacheForRemoval takes dir's run lock exclusively, non-blocking.
// busy=true means a live run holds it and the cache must be left alone. On
// success the caller removes the cache dir and the lock file, then unlocks,
// the same unlock-after-removal rule sweepCSBundle follows, so a blocked
// acquirer never sees a half-removed tree.
func lockRootfsCacheForRemoval(dir string) (unlock func(), busy bool, err error) {
	l, err := acquireFlock(rootfsCacheLockPath(dir), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		if errors.Is(err, errCacheBusy) {
			return func() {}, true, nil
		}
		return func() {}, false, err
	}
	return func() { l.Close() }, false, nil
}

// removeRootfsCache removes dir and its guarding lock file under an
// exclusive run lock, returning errCacheBusy (wrapped) when a live holder
// pins the cache: a running guest for a published dir, a mid-flight unpack
// for a staging dir (both hold the digest's lock, see rootfsCacheLockPath).
// The lock comes first even when dir is already gone: a vanished staging
// dir usually means its unpack just renamed it into place, and the holder
// still owns the digest lock, which an unlocked cleanup here would unlink
// out from under it. A missing lock parent means nothing was ever unpacked
// or locked, so an rmi of a run-less image stays a no-op that conjures no
// store structure.
func removeRootfsCache(dir string) error {
	unlock, busy, err := lockRootfsCacheForRemoval(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer unlock()
	if busy {
		return fmt.Errorf("%s: %w", dir, errCacheBusy)
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.Remove(rootfsCacheLockPath(dir)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// removeRootfsCacheForDigest is the non-darwin removeRefCaches' plain-cache
// half: delete digest's unpacked plain rootfs, refusing while a live run uses
// it. The darwin removeRefCaches inlines the same removal because it deletes
// under a lock already held from its two-cache preflight.
func removeRootfsCacheForDigest(s *store, digest string) error {
	rootfs, err := defaultRootfsForDigest(s.root, digest)
	if err != nil {
		return err
	}
	if err := removeRootfsCache(rootfs); err != nil {
		if errors.Is(err, errCacheBusy) {
			return fmt.Errorf(
				"cache for %s is in use by a live run; stop it before removing the image",
				digest)
		}
		return err
	}
	return nil
}

// PreserveAcrossExec clears FD_CLOEXEC on the lock's descriptor so the flock
// rides through syscall.Exec into the replacement process and is released by
// the kernel exactly when that process exits, SIGKILL included.
func (l *flockFile) PreserveAcrossExec() error {
	_, err := unix.FcntlInt(l.f.Fd(), unix.F_SETFD, 0)
	return err
}
