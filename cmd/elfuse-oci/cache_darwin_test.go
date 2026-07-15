// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func withDarwinCacheSeams(t *testing.T, isMount func(string) bool, detach func(string) error) {
	t.Helper()
	oldIsMount := isMountPointFn
	oldDetach := detachForce
	if isMount != nil {
		isMountPointFn = isMount
	}
	if detach != nil {
		detachForce = detach
	}
	t.Cleanup(func() {
		isMountPointFn = oldIsMount
		detachForce = oldDetach
	})
}

// holdRunLock takes a shared run.lock on the bundle for the test's lifetime,
// simulating a live run so a sweep sees the bundle busy.
func holdRunLock(t *testing.T, bundle string) {
	t.Helper()
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := acquireFlock(runLockPath(bundle), syscall.LOCK_SH)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
}

func writeSparseBundleMarker(t *testing.T, bundle string) {
	t.Helper()
	image := filepath.Join(bundle, "rootfs.sparsebundle")
	if err := os.MkdirAll(image, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(image, "band"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinCacheExistsBundleAndPlainRootfs(t *testing.T) {
	root := t.TempDir()
	digest := "sha256:" + strings.Repeat("1", 64)
	if cacheExists(root, digest) {
		t.Fatal("cacheExists returned true for absent cache")
	}

	bundle, err := csBundleDirForDigest(root, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if !cacheExists(root, digest) {
		t.Fatal("cacheExists returned false for sparsebundle cache")
	}
	if err := os.RemoveAll(bundle); err != nil {
		t.Fatal(err)
	}

	rootfs, err := defaultRootfsForDigest(root, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	if !cacheExists(root, digest) {
		t.Fatal("cacheExists returned false for plain rootfs cache")
	}
	if cacheExists(root, "not-a-digest") {
		t.Fatal("cacheExists returned true for invalid digest")
	}
}

func TestDarwinCacheHasKeptData(t *testing.T) {
	root := t.TempDir()
	digest := "sha256:" + strings.Repeat("6", 64)

	if kept, err := cacheHasKeptData(root, digest); err != nil || kept {
		t.Fatalf("cacheHasKeptData absent = (%v, %v), want (false, nil)", kept, err)
	}

	bundle, err := csBundleDirForDigest(root, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	// A bundle from a normal (non-keep) run has no sidecar: not kept.
	if kept, err := cacheHasKeptData(root, digest); err != nil || kept {
		t.Fatalf("cacheHasKeptData no-sidecar = (%v, %v), want (false, nil)", kept, err)
	}

	if err := os.WriteFile(keptSidecarPath(bundle), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if kept, err := cacheHasKeptData(root, digest); err != nil || !kept {
		t.Fatalf("cacheHasKeptData with sidecar = (%v, %v), want (true, nil)", kept, err)
	}
}

// TestDarwinRmiRefusesKeptCacheWithoutForce pins the one case rmi still refuses:
// a bundle holding run --keep retained output is not discarded without --force,
// and --force then drops the whole bundle and removes the image.
func TestDarwinRmiRefusesKeptCacheWithoutForce(t *testing.T) {
	withDarwinCacheSeams(t, func(string) bool { return false }, nil)
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	digest, err := s.addImage("local:a", img)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := csBundleDirForDigest(s.root, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keptSidecarPath(bundle), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := s.rmi("local:a", false); err == nil || !strings.Contains(err.Error(), "keep") {
		t.Fatalf("rmi kept cache without --force err = %v, want --keep refusal", err)
	}
	if _, err := s.digestFor("local:a"); err != nil {
		t.Fatalf("pin lost after refused rmi: %v", err)
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("bundle removed after refused rmi: %v, want present", err)
	}

	rep, err := s.rmi("local:a", true)
	if err != nil {
		t.Fatalf("rmi --force kept cache: %v", err)
	}
	if !rep.CacheDropped {
		t.Error("rmi --force did not report dropping the cache")
	}
	if _, err := os.Stat(bundle); !os.IsNotExist(err) {
		t.Fatalf("bundle after rmi --force: %v, want removed", err)
	}
	if _, err := s.digestFor("local:a"); err == nil {
		t.Error("pin present after rmi --force, want gone")
	}
}

func TestDarwinRemoveRefCachesDropsBundleAndRootfs(t *testing.T) {
	withDarwinCacheSeams(t, func(string) bool { return false }, nil)
	s := &store{root: t.TempDir()}
	digest := "sha256:" + strings.Repeat("2", 64)
	bundle, err := csBundleDirForDigest(s.root, digest)
	if err != nil {
		t.Fatal(err)
	}
	rootfs, err := defaultRootfsForDigest(s.root, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := removeRefCaches(s, digest); err != nil {
		t.Fatalf("removeRefCaches: %v", err)
	}
	for _, p := range []string{bundle, rootfs} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s after removeRefCaches: %v, want IsNotExist", p, err)
		}
	}
}

func TestDarwinRemoveRefCachesDetachesMountedBundle(t *testing.T) {
	s := &store{root: t.TempDir()}
	digest := "sha256:" + strings.Repeat("3", 64)
	bundle, err := csBundleDirForDigest(s.root, digest)
	if err != nil {
		t.Fatal(err)
	}
	mnt := filepath.Join(bundle, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	var detached string
	withDarwinCacheSeams(t,
		func(path string) bool { return path == mnt },
		func(path string) error {
			detached = path
			return nil
		},
	)

	// No run holds run.lock, so the still-attached mount is stale: the sweep
	// detaches it and the bundle is removed.
	if err := removeRefCaches(s, digest); err != nil {
		t.Fatalf("removeRefCaches: %v", err)
	}
	if detached != mnt {
		t.Fatalf("detached = %q, want %q", detached, mnt)
	}
	if _, err := os.Stat(bundle); !os.IsNotExist(err) {
		t.Fatalf("bundle after removeRefCaches: %v, want IsNotExist", err)
	}
}

func TestDarwinPruneCachesDropsOrphanAndLegacyCSBundles(t *testing.T) {
	withDarwinCacheSeams(t, func(string) bool { return false }, nil)
	s := openTestStore(t)
	liveDigest := "sha256:" + strings.Repeat("4", 64)
	orphanDigest := "sha256:" + strings.Repeat("5", 64)
	if err := s.savePins(refPins{"live": liveDigest}); err != nil {
		t.Fatal(err)
	}
	liveBundle, _ := csBundleDirForDigest(s.root, liveDigest)
	orphanBundle, _ := csBundleDirForDigest(s.root, orphanDigest)
	legacyBundle := filepath.Join(s.root, "cs", "legacy_ref")
	for _, bundle := range []string{liveBundle, orphanBundle, legacyBundle} {
		writeSparseBundleMarker(t, bundle)
	}

	rep, err := s.pruneCaches(pruneOpts{cache: true})
	if err != nil {
		t.Fatalf("pruneCaches: %v", err)
	}
	if !slices.Contains(rep.CacheDirs, orphanBundle) || !slices.Contains(rep.CacheDirs, legacyBundle) {
		t.Fatalf("pruneCaches dirs = %v, want orphan and legacy bundles", rep.CacheDirs)
	}
	if slices.Contains(rep.CacheDirs, liveBundle) {
		t.Fatalf("pruneCaches dropped live bundle %s: %v", liveBundle, rep.CacheDirs)
	}
	if _, err := os.Stat(orphanBundle); !os.IsNotExist(err) {
		t.Fatalf("orphan bundle after prune: %v, want IsNotExist", err)
	}
	if _, err := os.Stat(legacyBundle); !os.IsNotExist(err) {
		t.Fatalf("legacy bundle after prune: %v, want IsNotExist", err)
	}
	if _, err := os.Stat(liveBundle); err != nil {
		t.Fatalf("live bundle after prune: %v, want present", err)
	}
}

// TestDarwinPruneCSBundleDryRunDoesNotSweepOrDelete pins that a dry-run makes
// the same decisions as a real prune (report the clones a real sweep would
// reap, skip a busy bundle) while never detaching or removing anything. The
// busy check is a real (non-blocking) probe of the bundle locks.
func TestDarwinPruneCSBundleDryRunDoesNotSweepOrDelete(t *testing.T) {
	key := filepath.Join("sha256", strings.Repeat("6", 64))
	dryRun := func(t *testing.T, bundle string) pruneReport {
		t.Helper()
		rep, err := pruneCSBundle(pruneReport{}, bundle, key, nil, pruneOpts{cache: true, dryRun: true})
		if err != nil {
			t.Fatalf("pruneCSBundle dry-run: %v", err)
		}
		if _, err := os.Stat(bundle); err != nil {
			t.Fatalf("dry-run removed bundle: %v", err)
		}
		return rep
	}
	noDetach := func(t *testing.T, isMount func(string) bool) {
		t.Helper()
		withDarwinCacheSeams(t, isMount, func(string) error {
			t.Fatal("detachForce called during dry-run")
			return nil
		})
	}

	t.Run("unmounted bundle reported", func(t *testing.T) {
		bundle := filepath.Join(t.TempDir(), "bundle")
		writeSparseBundleMarker(t, bundle)
		noDetach(t, func(string) bool { return false })

		rep := dryRun(t, bundle)
		if len(rep.CacheDirs) != 1 || rep.CacheDirs[0] != bundle {
			t.Fatalf("dry-run dirs = %v, want [%s]", rep.CacheDirs, bundle)
		}
	})

	t.Run("sweepable clone reported", func(t *testing.T) {
		bundle := filepath.Join(t.TempDir(), "bundle")
		writeSparseBundleMarker(t, bundle)
		mnt := filepath.Join(bundle, "mnt")
		orphan := filepath.Join(mnt, "run-42-1")
		if err := os.MkdirAll(orphan, 0o755); err != nil {
			t.Fatal(err)
		}
		noDetach(t, func(path string) bool { return path == mnt })

		rep := dryRun(t, bundle)
		if len(rep.CacheDirs) != 2 || rep.CacheDirs[0] != orphan || rep.CacheDirs[1] != bundle {
			t.Fatalf("dry-run dirs = %v, want [%s %s]", rep.CacheDirs, orphan, bundle)
		}
		if rep.Bytes == 0 {
			t.Fatal("dry-run Bytes = 0, want the bundle's on-disk size counted")
		}
		if _, err := os.Stat(orphan); err != nil {
			t.Fatalf("dry-run reaped %s, want read-only: %v", orphan, err)
		}
	})

	t.Run("busy bundle skipped", func(t *testing.T) {
		bundle := filepath.Join(t.TempDir(), "bundle")
		writeSparseBundleMarker(t, bundle)
		mnt := filepath.Join(bundle, "mnt")
		noDetach(t, func(path string) bool { return path == mnt })
		holdRunLock(t, bundle) // a live run holds run.lock

		rep := dryRun(t, bundle)
		if len(rep.CacheDirs) != 0 {
			t.Fatalf("dry-run dirs = %v, want empty for a busy bundle", rep.CacheDirs)
		}
		if rep.Bytes != 0 {
			t.Fatalf("dry-run Bytes = %d, want 0 for a busy bundle", rep.Bytes)
		}
	})
}

// TestDarwinSweepCSBundleIdleReapsAndHoldsLocks pins that an idle bundle
// (no run holds run.lock) is swept: a mounted volume's sweepable clones are
// reaped, the stale mount detached, and the returned unlock releases the
// bundle locks the sweep held for the caller's removal.
func TestDarwinSweepCSBundleIdleReapsAndHoldsLocks(t *testing.T) {
	unmounted := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(unmounted, 0o755); err != nil {
		t.Fatal(err)
	}
	withDarwinCacheSeams(t, func(string) bool { return false }, func(string) error {
		t.Fatal("detachForce called for non-mount")
		return nil
	})
	reaped, busy, unlock, err := sweepCSBundle(unmounted)
	if err != nil {
		t.Fatalf("sweepCSBundle no mount: %v", err)
	}
	if busy || len(reaped) != 0 {
		t.Fatalf("sweepCSBundle no mount = (reaped %v, busy %v), want idle empty", reaped, busy)
	}
	// While the sweep holds the locks, a would-be run's exclusive probe fails.
	if _, err := acquireFlock(runLockPath(unmounted), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, errCacheBusy) {
		t.Fatalf("run.lock during sweep err = %v, want held", err)
	}
	unlock()
	if free, err := acquireFlock(runLockPath(unmounted), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("run.lock after unlock err = %v, want free", err)
	} else {
		free.Close()
	}

	bundle := filepath.Join(t.TempDir(), "bundle")
	mnt := filepath.Join(bundle, "mnt")
	clone := filepath.Join(mnt, "run-1-1")
	if err := os.MkdirAll(clone, 0o755); err != nil {
		t.Fatal(err)
	}
	var detached string
	withDarwinCacheSeams(t,
		func(path string) bool { return path == mnt },
		func(path string) error { detached = path; return nil },
	)
	reaped, busy, unlock, err = sweepCSBundle(bundle)
	if err != nil {
		t.Fatalf("sweepCSBundle mounted: %v", err)
	}
	defer unlock()
	if busy {
		t.Fatal("sweepCSBundle mounted-but-idle reported busy")
	}
	if len(reaped) != 1 || reaped[0] != clone {
		t.Fatalf("mounted reaped = %v, want [%s]", reaped, clone)
	}
	if detached != mnt {
		t.Fatalf("detached = %q, want %q", detached, mnt)
	}
	if _, err := os.Stat(clone); !os.IsNotExist(err) {
		t.Fatalf("sweepable clone not reaped: %v", err)
	}
}

// TestDarwinSweepCSBundleBusySkips pins that a bundle whose run.lock a live
// run holds is reported busy and NOT force-detached.
func TestDarwinSweepCSBundleBusySkips(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "bundle")
	mnt := filepath.Join(bundle, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	withDarwinCacheSeams(t,
		func(path string) bool { return path == mnt },
		func(string) error {
			t.Fatal("detachForce called although a live run holds the volume")
			return nil
		},
	)
	holdRunLock(t, bundle)

	reaped, busy, unlock, err := sweepCSBundle(bundle)
	if err != nil {
		t.Fatalf("sweepCSBundle: %v", err)
	}
	defer unlock()
	if !busy {
		t.Fatal("sweepCSBundle did not report busy for a live run")
	}
	if len(reaped) != 0 {
		t.Fatalf("reaped = %v, want empty", reaped)
	}
}

// TestDarwinPruneCSBundleSkipsLivePinnedBeforeSweep pins the guard order: a
// still-pinned digest's bundle is skipped by a non---all prune before any
// sweep runs, so an active run's mount is never probed or detached.
func TestDarwinPruneCSBundleSkipsLivePinnedBeforeSweep(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "bundle")
	writeSparseBundleMarker(t, bundle)
	key := filepath.Join("sha256", strings.Repeat("7", 64))
	withDarwinCacheSeams(t,
		func(string) bool {
			t.Fatal("isMountPoint probed for a live pinned bundle")
			return false
		},
		func(string) error {
			t.Fatal("detachForce called for a live pinned bundle")
			return nil
		},
	)

	rep, err := pruneCSBundle(pruneReport{}, bundle, key, map[string]bool{key: true}, pruneOpts{cache: true})
	if err != nil {
		t.Fatalf("pruneCSBundle: %v", err)
	}
	if len(rep.CacheDirs) != 0 || rep.Bytes != 0 {
		t.Fatalf("live pinned bundle was touched: %+v", rep)
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("live pinned bundle missing after prune: %v", err)
	}
}

// TestDarwinPruneCSBundleLeavesBusyBundle pins that even when the sweep runs
// (e.g. --all), a bundle whose volume hosts a live run is left in place.
func TestDarwinPruneCSBundleLeavesBusyBundle(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "bundle")
	mnt := filepath.Join(bundle, "mnt")
	writeSparseBundleMarker(t, bundle)
	key := filepath.Join("sha256", strings.Repeat("8", 64))
	withDarwinCacheSeams(t,
		func(path string) bool { return path == mnt },
		func(string) error {
			t.Fatal("detachForce called although a live run holds the volume")
			return nil
		},
	)
	holdRunLock(t, bundle)

	rep, err := pruneCSBundle(pruneReport{}, bundle, key, map[string]bool{key: true}, pruneOpts{cache: true, all: true})
	if err != nil {
		t.Fatalf("pruneCSBundle: %v", err)
	}
	if len(rep.CacheDirs) != 0 {
		t.Fatalf("busy bundle reported as pruned: %v", rep.CacheDirs)
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("busy bundle missing after prune: %v", err)
	}
}

// TestDarwinRemoveRefCachesRefusesLiveRun pins the rmi --force guard: a
// volume whose run.lock a live run holds must refuse cache removal instead of
// force-detaching the guest's rootfs.
func TestDarwinRemoveRefCachesRefusesLiveRun(t *testing.T) {
	s := &store{root: t.TempDir()}
	digest := "sha256:" + strings.Repeat("7", 64)
	bundle, err := csBundleDirForDigest(s.root, digest)
	if err != nil {
		t.Fatal(err)
	}
	mnt := filepath.Join(bundle, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	detached := false
	withDarwinCacheSeams(t,
		func(path string) bool { return path == mnt },
		func(string) error {
			detached = true
			return nil
		},
	)
	holdRunLock(t, bundle)

	err = removeRefCaches(s, digest)
	if err == nil || !strings.Contains(err.Error(), "in use by a live run") {
		t.Fatalf("removeRefCaches err = %v, want live-run refusal", err)
	}
	if detached {
		t.Fatal("removeRefCaches force-detached a live run's volume")
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("bundle after refusal: %v, want untouched", err)
	}
}

// TestDarwinSweepCSBundleRejectsSymlinkedMnt pins S8: a tampered store whose
// mnt is a symlink at an unrelated volume must be refused before any mount
// probe, clone reap, or detach, so the sweep cannot force-detach or wipe that
// volume. provisionCaseSensitive guards its attach path the same way.
func TestDarwinSweepCSBundleRejectsSymlinkedMnt(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "unrelated-volume")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	mnt := filepath.Join(bundle, "mnt")
	if err := os.Symlink(victim, mnt); err != nil {
		t.Fatal(err)
	}
	withDarwinCacheSeams(t,
		func(string) bool {
			t.Fatal("isMountPoint probed a symlinked mnt")
			return false
		},
		func(string) error {
			t.Fatal("detachForce followed a symlinked mnt")
			return nil
		},
	)

	_, _, unlock, err := sweepCSBundle(bundle)
	if unlock != nil {
		unlock()
	}
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("sweepCSBundle symlinked mnt err = %v, want symlink refusal", err)
	}
	if _, err := os.Lstat(mnt); err != nil {
		t.Fatalf("symlink mnt disturbed: %v", err)
	}
}

// TestDarwinRemoveRefCachesBusyPlainRootfsLeavesBundle pins #16: when a digest
// has both cache forms and a live --plain-rootfs run holds the plain rootfs
// lock, removeRefCaches must refuse before deleting either form, so the
// sparsebundle is not left half-removed under a still-live pin. The bundle
// survives and the plain rootfs is untouched.
func TestDarwinRemoveRefCachesBusyPlainRootfsLeavesBundle(t *testing.T) {
	withDarwinCacheSeams(t,
		func(string) bool { return false },
		func(string) error {
			t.Fatal("detachForce called although the plain rootfs run is live")
			return nil
		},
	)
	s := &store{root: t.TempDir()}
	digest := "sha256:" + strings.Repeat("9", 64)
	bundle, err := csBundleDirForDigest(s.root, digest)
	if err != nil {
		t.Fatal(err)
	}
	rootfs, err := defaultRootfsForDigest(s.root, digest)
	if err != nil {
		t.Fatal(err)
	}
	writeSparseBundleMarker(t, bundle)
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	// A live --plain-rootfs run holds the plain rootfs lock shared.
	hold, err := acquireRootfsRunLock(rootfs)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()

	err = removeRefCaches(s, digest)
	if err == nil || !strings.Contains(err.Error(), "in use by a live run") {
		t.Fatalf("removeRefCaches err = %v, want live-run refusal", err)
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("sparsebundle removed despite refusal (half-deleted cache): %v", err)
	}
	if _, err := os.Stat(rootfs); err != nil {
		t.Fatalf("plain rootfs removed despite refusal: %v", err)
	}
}
