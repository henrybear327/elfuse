// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package main

import "os"

// On non-Darwin the case-sensitive sparsebundle path is unavailable (no APFS,
// no hdiutil, no clonefile), so an unpacked cache is only ever the plain
// rootfs/<algo>/<hex> directory. The lifecycle primitives (rmi, prune) touch
// caches through cacheExists / removeRefCaches / pruneCaches so the pure-Go
// blob GC and the rootfs cache sweep build and test on Linux CI; the darwin
// sparsebundle sweep lives in cache_darwin.go.

// cacheHasKeptData reports whether digest's cache holds run --keep retained
// output. On non-Darwin the only cache is a plain rootfs directory with no
// per-run COW clones, so there is never retained output to protect: rmi always
// reclaims it.
func cacheHasKeptData(root, digest string) (bool, error) {
	return false, nil
}

// cacheExists reports whether digest has an unpacked cache under the store. On
// non-Darwin this is just the plain rootfs directory.
func cacheExists(root, digest string) bool {
	rootfs, err := defaultRootfsForDigest(root, digest)
	if err != nil {
		return false
	}
	if _, err := os.Stat(rootfs); err == nil {
		return true
	}
	return false
}

// removeRefCaches deletes digest's unpacked cache(s). On non-Darwin, the plain
// rootfs directory only, refusing while a live run holds its per-digest lock.
func removeRefCaches(s *store, digest string) error {
	return removeRootfsCacheForDigest(s, digest)
}

// pruneCaches drops elfuse's unpacked caches. Without opts.all, only caches for
// refs no longer pinned (orphan caches) are dropped; with opts.all, every
// cache. On non-Darwin only plain rootfs/<algo>/<hex> directories exist; the
// rootfs sweep is shared via pruneRootfsCaches.
func (s *store) pruneCaches(opts pruneOpts) (pruneReport, error) {
	live, err := s.liveCacheKeys()
	if err != nil {
		return pruneReport{}, err
	}
	return pruneRootfsCaches(s, live, opts)
}
