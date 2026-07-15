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

// legacyCacheNameForRef reproduces the pre-digest cache naming scheme, which
// flattened the ref itself into a single (intentionally lossy) path
// component. New caches are keyed by digest (cacheKeyForDigest); this helper
// survives to document the old layout.
func legacyCacheNameForRef(ref string) string {
	return strings.NewReplacer("/", "_", ":", "_", "@", "_").Replace(ref)
}

// cacheKeyForDigest returns the relative cache key used under rootfs/ and cs/.
// The current store writes sha256 blobs only; keep the algorithm component in
// the path so the layout remains explicit and non-lossy.
func cacheKeyForDigest(digest string) (string, error) {
	h, err := v1.NewHash(digest)
	if err != nil {
		return "", err
	}
	if h.Algorithm != "sha256" || h.Hex == "" {
		return "", fmt.Errorf("unsupported cache digest %q", digest)
	}
	return filepath.Join(h.Algorithm, h.Hex), nil
}

func defaultRootfsForDigest(store, digest string) (string, error) {
	key, err := cacheKeyForDigest(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(store, rootfsCacheDirName, key), nil
}

func legacyRootfsForRef(store, ref string) string {
	return filepath.Join(store, rootfsCacheDirName, legacyCacheNameForRef(ref))
}
