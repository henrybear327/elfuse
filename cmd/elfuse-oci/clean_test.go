// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seedCleanStore(t *testing.T) *store {
	t.Helper()
	s, _ := storeWithImage(t, "x:1", testImage{})
	for _, d := range []string{
		filepath.Join(s.root, "rootfs", "sha256", strings.Repeat("a", 64)),
		filepath.Join(s.root, "cs", "sha256", strings.Repeat("b", 64), "mnt"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestCleanCacheKeepsBlobsAndPins(t *testing.T) {
	installFakeHdiutil(t)
	s := seedCleanStore(t)
	var err error
	_, stderr := captureOutput(t, func() {
		err = cmdClean([]string{"--store", s.root, "--cache"})
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, stderr, "Removed caches")
	for _, gone := range []string{"rootfs", "cs"} {
		if _, err := os.Lstat(filepath.Join(s.root, gone)); !os.IsNotExist(err) {
			t.Errorf("%s must be removed: %v", gone, err)
		}
	}
	for _, kept := range []string{"blobs", "refs.json"} {
		if _, err := os.Lstat(filepath.Join(s.root, kept)); err != nil {
			t.Errorf("%s must survive --cache: %v", kept, err)
		}
	}
	// The pin still resolves, so the next run only re-unpacks.
	if _, err := s.digestFor("x:1", defaultPlatform); err != nil {
		t.Fatal(err)
	}
}

func TestCleanNukesWholeStore(t *testing.T) {
	installFakeHdiutil(t)
	s := seedCleanStore(t)
	var err error
	_, stderr := captureOutput(t, func() {
		err = cmdClean([]string{"--store", s.root})
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, stderr, "Removed store")
	entries, err := os.ReadDir(s.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != ".lock" {
			t.Errorf("leftover %s", e.Name())
		}
	}
	// A nuked store reopens from nothing.
	if _, err := openStore(s.root); err != nil {
		t.Fatal(err)
	}
}

func TestCleanMissingStoreIsNoop(t *testing.T) {
	installFakeHdiutil(t)
	var err error
	_, stderr := captureOutput(t, func() {
		err = cmdClean([]string{"--store", filepath.Join(t.TempDir(), "never")})
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, stderr, "Nothing to clean")
}

func TestCleanRejectsPositional(t *testing.T) {
	var err error
	captureOutput(t, func() { err = cmdClean([]string{"x:1"}) })
	if err == nil || !strings.Contains(err.Error(), "clean:") {
		t.Fatalf("err = %v", err)
	}
}

// clean is the recovery path, so a malformed cs cache (a file where the
// sha256 directory belongs) is removed rather than failed on.
func TestCleanCacheRemovesMalformedCS(t *testing.T) {
	installFakeHdiutil(t)
	s := seedCleanStore(t)
	os.RemoveAll(s.cacheBase(cacheCS))
	if err := os.WriteFile(s.cacheBase(cacheCS), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var err error
	captureOutput(t, func() { err = cmdClean([]string{"--store", s.root, "--cache"}) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(s.root, cacheCS)); !os.IsNotExist(err) {
		t.Fatalf("cs must be removed: %v", err)
	}
}
