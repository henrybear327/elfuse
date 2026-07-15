// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1"
)

// Store subdirectories holding unpacked caches, keyed by cacheKeyForDigest:
// plain rootfs trees and (darwin) case-sensitive sparsebundle bundles.
const (
	rootfsCacheDirName = "rootfs"
	csCacheDirName     = "cs"
)

// cacheKeyForDigest returns the relative cache key used under rootfs/ and cs/.
// The current store writes sha256 blobs only; keep the algorithm component in
// the path so the layout remains explicit and non-lossy.
func cacheKeyForDigest(digest string) (string, error) {
	h, err := v1.NewHash(digest)
	if err != nil {
		return "", err
	}
	if h.Algorithm != "sha256" || h.Hex == "" {
		// Unreachable with the pinned go-containerregistry, whose NewHash
		// accepts sha256 only: a version-independence guard, not a reachable
		// validation. The store layout and prune's rootfs/sha256 sweep assume
		// sha256 keys, so an upstream that starts accepting more algorithms
		// must fail here rather than mint keys the sweeps misread.
		return "", fmt.Errorf("unsupported cache digest %q", digest)
	}
	return filepath.Join(h.Algorithm, h.Hex), nil
}

// insideStore reports whether path lies under one of the store's managed
// trees (the rootfs/ digest caches or the cs/ bundle dirs). Lexical only:
// the caller guards a user-supplied --rootfs against naming a tree the
// store's sweeps may reclaim, and a symlinked alias of the store is that
// user's own arrangement.
func insideStore(store, path string) bool {
	for _, base := range []string{
		filepath.Join(store, rootfsCacheDirName),
		filepath.Join(store, csCacheDirName),
	} {
		rel, err := filepath.Rel(base, filepath.Clean(path))
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." &&
			!strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return true
		}
	}
	return false
}

func defaultRootfsForDigest(store, digest string) (string, error) {
	key, err := cacheKeyForDigest(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(store, rootfsCacheDirName, key), nil
}

// csBundleDirForDigest is <store>/cs/<algo>/<hex>: it holds the case-sensitive
// sparsebundle image and the attach mount point for one pinned manifest digest.
func csBundleDirForDigest(store, digest string) (string, error) {
	key, err := cacheKeyForDigest(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(store, csCacheDirName, key), nil
}
