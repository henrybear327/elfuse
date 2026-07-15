// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// On Darwin an unpacked cache can be either (or both) of:
//   - a case-sensitive APFS sparsebundle bundle at cs/<algo>/<hex>/ holding the
//     warm unpacked base tree (image file rootfs.sparsebundle + mount point mnt),
//   - a plain rootfs/<algo>/<hex> directory (the --plain-rootfs path).
//
// cacheExists / removeRefCaches / pruneCaches are the lifecycle seam the
// cross-platform gc.go/rmi.go/prune.go code calls; the darwin versions add the
// sparsebundle lifecycle (detach a still-mounted volume before removing its
// bundle directory) on top of the shared rootfs sweep.

// cacheHasKeptData reports whether digest's cache holds run --keep retained
// output. A --keep run drops the `kept` sidecar beside the sparsebundle (outside
// the mounted volume, like the bundle flocks), so this is a cheap stat that does
// not need to attach a cold, detached bundle to inspect its clones. rmi refuses
// to reclaim such a cache without force.
func cacheHasKeptData(root, digest string) (bool, error) {
	bundle, err := csBundleDirForDigest(root, digest)
	if err != nil {
		// An unparseable digest key has no bundle and so no kept data; a real
		// rmi target is always a valid digest.
		return false, nil
	}
	if _, err := os.Stat(keptSidecarPath(bundle)); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	return false, nil
}

// cacheExists reports whether digest has any unpacked cache under the store: the
// case-sensitive sparsebundle bundle and/or the plain rootfs directory.
func cacheExists(root, digest string) bool {
	bundle, err := csBundleDirForDigest(root, digest)
	if err == nil {
		if _, err := os.Stat(bundle); err == nil {
			return true
		}
	}
	rootfs, err := defaultRootfsForDigest(root, digest)
	if err != nil {
		return false
	}
	if _, err := os.Stat(rootfs); err == nil {
		return true
	}
	return false
}

// removeRefCaches deletes digest's unpacked caches: the case-sensitive
// sparsebundle and the plain rootfs, when a digest has both. A crash leftover
// mount is recovered (orphan clones reaped, stale volume detached) so the
// bundle can be removed, but a volume that still hosts a live run's clone, or a
// plain rootfs a live --plain-rootfs run holds, refuses: dropping the cache
// (via rmi) means "reclaim derived state", not "rip the rootfs out from under a
// running guest".
//
// Both cache locks are preflighted before either form is deleted, so a busy
// side leaves BOTH caches intact. Deleting the sparsebundle first and only then
// discovering the plain rootfs is busy (or vice versa) would strand a
// half-deleted cache under a still-live pin. The plain reference lock is taken
// first, matching a run's acquisition order (reference lock, then bundle
// locks); both acquisitions are non-blocking, so the order cannot deadlock.
func removeRefCaches(s *store, digest string) error {
	bundle, err := csBundleDirForDigest(s.root, digest)
	if err != nil {
		return err
	}
	rootfs, err := defaultRootfsForDigest(s.root, digest)
	if err != nil {
		return err
	}
	busyErr := fmt.Errorf("cache for %s is in use by a live run; stop it before removing the image", digest)

	// Preflight the plain rootfs lock. An ENOENT (no rootfs/ scaffolding) means
	// no plain cache and no plain run can exist, so there is nothing to hold.
	rootfsUnlock, rootfsBusy, err := lockRootfsCacheForRemoval(rootfs)
	haveRootfsLock := err == nil
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if rootfsBusy {
		return busyErr
	}
	if haveRootfsLock {
		defer rootfsUnlock()
	}

	if _, err := os.Stat(bundle); err == nil {
		_, busy, unlock, err := sweepCSBundle(bundle)
		if err != nil {
			return err
		}
		if busy {
			// The plain lock (if held) is released by the deferred unlock; no
			// cache was deleted, so the refusal leaves both forms intact.
			return busyErr
		}
		// Hold the bundle locks across the removal: a concurrent run's
		// provision would otherwise race in between the sweep and the
		// RemoveAll and lose its freshly attached volume.
		err = os.RemoveAll(bundle)
		unlock()
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	// Plain rootfs, removed under the lock already held from the preflight.
	if haveRootfsLock {
		if err := os.RemoveAll(rootfs); err != nil {
			return err
		}
		if err := os.Remove(rootfsCacheLockPath(rootfs)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// pruneCaches drops elfuse's unpacked caches. Without opts.all, only caches for
// refs no longer pinned (orphan caches) are dropped; with opts.all, every
// cache. The plain rootfs sweep is shared (pruneRootfsCaches); the darwin-only
// sparsebundle sweep walks cs/<algo>/<hex>/ plus legacy cs/<name>/ directories,
// detaching a still-mounted volume before removing its bundle. The bytes
// reported for a sparsebundle are the on-disk allocation of its image file
// (dirSize of rootfs.sparsebundle), not the 16g virtual ceiling and not a live
// mount's contents.
func (s *store) pruneCaches(opts pruneOpts) (pruneReport, error) {
	live, err := s.liveCacheKeys()
	if err != nil {
		return pruneReport{}, err
	}
	rep, err := pruneRootfsCaches(s, live, opts)
	if err != nil {
		return rep, err
	}

	csBase := filepath.Join(s.root, csCacheDirName)
	entries, err := os.ReadDir(csBase)
	if err != nil {
		if os.IsNotExist(err) {
			return rep, nil
		}
		return rep, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		top := filepath.Join(csBase, e.Name())
		if e.Name() == "sha256" {
			children, err := os.ReadDir(top)
			if err != nil {
				return rep, err
			}
			for _, child := range children {
				if !child.IsDir() {
					continue
				}
				key := filepath.Join("sha256", child.Name())
				bundle := filepath.Join(top, child.Name())
				var err error
				rep, err = pruneCSBundle(rep, bundle, key, live, opts)
				if err != nil {
					return rep, err
				}
			}
			continue
		}

		// Legacy ref-named sparsebundle caches are no longer live under the
		// digest-keyed scheme; prune --cache reclaims them as orphan caches.
		var err error
		rep, err = pruneCSBundle(rep, top, "", live, opts)
		if err != nil {
			return rep, err
		}
	}
	return rep, nil
}

func pruneCSBundle(rep pruneReport, bundle, key string, live map[string]bool, opts pruneOpts) (pruneReport, error) {
	// A still-pinned digest is off-limits to a non---all prune BEFORE any
	// sweep: its attached volume may belong to an active run, and
	// sweepCSBundle cannot tell a crashed leftover mount from a live one by
	// mount state alone. A crashed pinned bundle's stale mount is recovered
	// by the next run's provision (which re-attaches cleanly) or by an
	// explicit prune --cache --all.
	if key != "" && !opts.all && live[key] {
		return rep, nil
	}

	// Crash recovery: if a killed run left this bundle's volume attached,
	// reap orphan COW clones inside it and detach the stale mount. If a live
	// run still owns a clone in the volume, leave the whole bundle alone;
	// force-detaching would rip the rootfs out from under that guest
	// (reachable with --all, or via a legacy/unpinned bundle). A dry-run
	// makes the same decisions read-only: it reports the orphan clones a
	// real prune would reap and skips a busy bundle a real prune would
	// leave, but never detaches or removes anything.
	if opts.dryRun {
		// A busy bundle (a live run holds run.lock) is left alone, exactly as
		// a real prune would; otherwise report the clones a real sweep would
		// reap. Read-only: probe the locks and list, never detach or remove.
		if csBundleBusy(bundle) {
			return rep, nil
		}
		mnt := filepath.Join(bundle, "mnt")
		if isMountPointFn(mnt) {
			rep.CacheDirs = append(rep.CacheDirs, listSweepableClones(mnt)...)
		}
		image := filepath.Join(bundle, "rootfs.sparsebundle")
		rep.Bytes += dirSize(image)
		rep.CacheDirs = append(rep.CacheDirs, bundle)
		return rep, nil
	}

	reaped, busy, unlock, err := sweepCSBundle(bundle)
	if err != nil {
		return rep, err
	}
	if len(reaped) > 0 {
		rep.CacheDirs = append(rep.CacheDirs, reaped...)
	}
	if busy {
		return rep, nil
	}

	image := filepath.Join(bundle, "rootfs.sparsebundle")
	rep.Bytes += dirSize(image)
	// sweepCSBundle already detached a stale mount if there was one, and holds
	// the bundle locks so a concurrent provision cannot re-populate the bundle
	// between here and the removal.
	err = os.RemoveAll(bundle)
	unlock()
	if err != nil {
		return rep, err
	}
	rep.CacheDirs = append(rep.CacheDirs, bundle)
	return rep, nil
}

// sweepCSBundle performs crash recovery for one sparsebundle bundle under the
// per-bundle advisory flocks. It acquires attach.lock and run.lock
// exclusively (non-blocking): if either is held, a live run (or an in-flight
// provision) owns the bundle, so it returns busy=true without touching
// anything. Holding run.lock exclusively proves no run is executing out of the
// volume, so every clone left inside is abandoned by construction: reap the
// sweepable ones (all but --keep-marked clones, plus unpack leftovers) and
// detach a still-attached stale mount.
//
// On success it returns the reaped clone directories and an unlock func that
// releases both locks. The caller must invoke unlock AFTER it finishes with
// the bundle (typically after os.RemoveAll), so a concurrent provision cannot
// re-attach and re-populate the bundle in the gap. On busy or error the
// returned unlock is a non-nil no-op, so callers may always defer it.
func sweepCSBundle(bundle string) (reaped []string, busy bool, unlock func(), err error) {
	noop := func() {}
	attachLock, err := acquireFlock(attachLockPath(bundle), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		if errors.Is(err, errCacheBusy) {
			return nil, true, noop, nil
		}
		return nil, false, noop, err
	}
	runLock, err := acquireFlock(runLockPath(bundle), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		attachLock.Close()
		if errors.Is(err, errCacheBusy) {
			return nil, true, noop, nil
		}
		return nil, false, noop, err
	}
	release := func() {
		runLock.Close()
		attachLock.Close()
	}

	mnt := filepath.Join(bundle, "mnt")
	// Reject a symlinked mount path before any mount-status probe, clone reap,
	// or detach: isMountPoint (os.Stat) and detachForce follow the link, so a
	// tampered store with mnt symlinked at an unrelated attached volume would
	// otherwise get that volume's contents reaped and the volume force-detached.
	// provisionCaseSensitive guards its own attach path the same way; the
	// destructive sweep (prune --cache, rmi) needs the guard too.
	if li, err := os.Lstat(mnt); err == nil && li.Mode()&os.ModeSymlink != 0 {
		release()
		return nil, false, noop, fmt.Errorf("mount path %s is a symlink; refusing to detach/reap", mnt)
	}
	if isMountPointFn(mnt) {
		reaped = reapSweepableClones(mnt)
		if err := detachForce(mnt); err != nil {
			release()
			return reaped, false, noop, fmt.Errorf("detach %s: %w", mnt, err)
		}
	}
	return reaped, false, release, nil
}
