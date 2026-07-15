// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Per-run COW clones of the warm base tree live inside an attached sparsebundle
// volume as run-<pid>-<nanosec> directories (see csrun.go). A crashed unpack
// can also leave a rootfs.tmp-<random> staging directory behind (see
// unpackImage). Liveness is decided by the per-bundle advisory flocks
// (bundlelock.go), never by pids: a sweep only reaps once it holds run.lock
// exclusively, which proves no run is executing out of the volume, so every
// clone it finds is abandoned by construction. Pid parsing is gone; pid
// reuse can no longer make a still-wanted clone look dead.
//
// A run started with --keep records a keep sidecar for its clone so the sweep
// preserves it; without the sidecar every run-* clone is reapable.
//
// These helpers are pure path/lock logic with no darwin-specific calls, so
// they build and unit-test on Linux; sweepCSBundle (which needs isMountPoint +
// detachForce) is darwin-only and lives in cache_darwin.go.

// keepDirName is a mount-root directory holding one marker file per kept clone,
// named by clone directory name. It lives in the mount root, BESIDE the clones,
// never inside any clone: a clone directory is a guest's /, so a marker there
// would collide with an image that ships its own /.elfuse-keep and could be
// forged by the guest at runtime, either of which would make an ordinary run's
// clone masquerade as kept and leak past every sweep. The mount root is outside
// every guest's --sysroot view, so markers here are writable only by
// elfuse-oci. A sweep skips a clone whose marker is present; only
// whole-bundle removal (prune of an unpinned/--all bundle, rmi --force)
// reclaims a kept clone, and that deletes this directory with it.
const keepDirName = ".elfuse-keep"

// keepDirPath returns the mount-root keep-marker directory.
func keepDirPath(mountPath string) string {
	return filepath.Join(mountPath, keepDirName)
}

// cloneKeepMarkerPath returns the keep marker path for the clone named
// cloneName under mountPath.
func cloneKeepMarkerPath(mountPath, cloneName string) string {
	return filepath.Join(keepDirPath(mountPath), cloneName)
}

// writeKeepMarker records that the COW clone at cloneDir should survive sweeps,
// via a marker in the mount-root keep directory, so a later sweep preserves it
// after the creating run has exited and released run.lock.
func writeKeepMarker(cloneDir string) error {
	mountPath := filepath.Dir(cloneDir)
	if err := os.MkdirAll(keepDirPath(mountPath), 0o755); err != nil {
		return err
	}
	return touchFile(cloneKeepMarkerPath(mountPath, filepath.Base(cloneDir)))
}

// touchFile creates (or truncates) an empty marker file. The markers carry
// no content; only their existence matters.
func touchFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

// isRunCloneDir reports whether a directory entry name is a per-run COW clone
// (run-<pid>-<nanosec>). The pid is not parsed; only the naming matters.
func isRunCloneDir(name string) bool {
	return strings.HasPrefix(name, "run-")
}

// isUnpackTempDir reports whether name is a leftover unpack staging directory
// (rootfs.tmp-<random>) from a crashed unpackImage into the volume.
func isUnpackTempDir(name string) bool {
	return strings.HasPrefix(name, "rootfs.tmp-")
}

// listSweepableClones returns the reapable directories inside mountPath: every
// run-<pid>-<ns> clone WITHOUT a keep marker, plus any rootfs.tmp-* unpack
// leftover. The caller must hold run.lock exclusively (no live run), so a
// clone lacking a keep marker is guaranteed abandoned. Removes nothing; it is
// the read-only detection half shared with prune --dry-run.
func listSweepableClones(mountPath string) []string {
	entries, err := os.ReadDir(mountPath)
	if err != nil {
		return nil
	}
	var sweepable []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case isRunCloneDir(name):
			if !e.IsDir() {
				continue
			}
			// Preserve the clone unless its keep marker is DEFINITIVELY
			// absent: err == nil means present, and a transient non-ENOENT
			// error (e.g. EIO on the mounted volume) must not cause a
			// --keep clone to be reaped; fail safe toward preservation.
			if _, err := os.Stat(cloneKeepMarkerPath(mountPath, name)); !os.IsNotExist(err) {
				continue
			}
			sweepable = append(sweepable, filepath.Join(mountPath, name))
		case isUnpackTempDir(name):
			sweepable = append(sweepable, filepath.Join(mountPath, name))
		}
	}
	return sweepable
}

// reapSweepableClones removes the directories listSweepableClones names.
// Removal is best-effort: a busy entry (e.g. still unmounting) is skipped and
// not reported. Returns the directories that were removed. The caller must
// hold run.lock exclusively.
func reapSweepableClones(mountPath string) []string {
	var reaped []string
	for _, dir := range listSweepableClones(mountPath) {
		if err := os.RemoveAll(dir); err != nil {
			continue // busy or evaporating; leave it for next time
		}
		reaped = append(reaped, dir)
	}
	return reaped
}

// csBundleBusy reports whether a live run holds the bundle via a non-blocking
// exclusive probe of run.lock. It is the read-only busy check used by prune
// --dry-run and diagnostics; it acquires and immediately releases, mutating
// nothing. It deliberately does NOT touch attach.lock: attach.lock is a
// lifecycle lock whose holders (provision, sweep, a run's last-one-out Close)
// each own the mount's detach fate, and a read-only prober transiently
// holding it would fool a concurrent Close into skipping its detach (leaving
// the volume attached with no owner). Any error other than a clean
// acquisition fails closed (busy) so a dry-run never advertises a reap it
// could not safely perform.
func csBundleBusy(bundle string) bool {
	r, err := acquireFlock(runLockPath(bundle), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return true
	}
	r.Close()
	return false
}
