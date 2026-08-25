// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestPinsPerPlatform(t *testing.T) {
	s := tempStore(t)
	arm := ocispec.Platform{OS: "linux", Architecture: "arm64"}
	amd := ocispec.Platform{OS: "linux", Architecture: "amd64"}
	pinImage(t, s, "alpine:3", arm, "sha256:aaa")
	pinImage(t, s, "alpine:3", amd, "sha256:bbb")
	for _, tc := range []struct {
		p    ocispec.Platform
		want string
	}{{arm, "sha256:aaa"}, {amd, "sha256:bbb"}} {
		got, err := s.digestFor("alpine:3", tc.p)
		if err != nil || got != tc.want {
			t.Fatalf("digestFor(%s) = %q, %v; want %q", platforms.Format(tc.p), got, err, tc.want)
		}
	}
}

func TestDigestForErrorKinds(t *testing.T) {
	s := tempStore(t)
	// Missing pin wraps errNotPulled and names the pull command.
	_, err := s.digestFor("absent:1", defaultPlatform)
	if !errors.Is(err, errNotPulled) {
		t.Fatalf("want errNotPulled, got %v", err)
	}
	if !strings.Contains(err.Error(), "elfuse-oci pull") {
		t.Fatalf("error should name the fix: %v", err)
	}
	// A corrupt table must error, not read as empty.
	for _, corrupt := range []string{"{", "null", `{"r": null}`} {
		if err := os.WriteFile(s.pinsPath(), []byte(corrupt), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := s.digestFor("absent:1", defaultPlatform); err == nil || errors.Is(err, errNotPulled) {
			t.Fatalf("corrupt refs.json %q: want a corruption error, got %v", corrupt, err)
		}
	}
}

func TestPinConcurrentWritersKeepAllEntries(t *testing.T) {
	s := tempStore(t)
	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ref := "img" + string(rune('a'+i)) + ":1"
			err := s.withLock(context.Background(), func() error { return s.pinLocked(ref, "linux/arm64", "sha256:x") })
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	p, err := s.loadPins()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != n {
		t.Fatalf("want %d pins after concurrent writers, got %d", n, len(p))
	}
}

// TestBlobLayout pins the on-disk shape the CI store seeding and the
// corrupt-layer test depend on: blobs/sha256/<hex>, committed read-only.
func TestBlobLayout(t *testing.T) {
	s := tempStore(t)
	desc := pushBlob(t, s, ocispec.MediaTypeImageConfig, []byte("{}"))
	fi, err := os.Stat(filepath.Join(s.root, "blobs", "sha256", desc.Digest.Encoded()))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o222 != 0 {
		t.Fatalf("blob mode %v has write bits", fi.Mode())
	}
}

func TestManifestAndConfigRoundTrip(t *testing.T) {
	s, d := storeWithImage(t, "fix:1", testImage{})
	m, err := s.manifestFor(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Layers) != 1 {
		t.Fatalf("want 1 layer, got %d", len(m.Layers))
	}
	_, cfg, err := s.configFor(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OS != "linux" || cfg.Architecture != "arm64" {
		t.Fatalf("config platform = %s/%s", cfg.OS, cfg.Architecture)
	}
}

// replaceFile removes its temp file when the create or the rename fails.
func TestReplaceFileLeavesNoLitterOnFailure(t *testing.T) {
	cases := []struct {
		name        string
		skipAsRoot  bool
		setup       func(t *testing.T, dir string)
		wantEntries []string
	}{
		{"create fails in read-only dir", true, func(t *testing.T, dir string) {
			if err := os.Chmod(dir, 0o555); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		}, nil},
		{"rename fails onto non-empty dir", false, func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "resolv.conf", "x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, []string{"resolv.conf"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipAsRoot && os.Geteuid() == 0 {
				t.Skip("directory write permissions do not bind as root")
			}
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			tc.setup(t, dir)

			if err := replaceFile(root, "resolv.conf", []byte("nameserver 8.8.8.8\n")); err == nil {
				t.Fatal("replaceFile succeeded, want error")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if !slices.Equal(names, tc.wantEntries) {
				t.Fatalf("entries after failed write = %v, want %v", names, tc.wantEntries)
			}
		})
	}
}

// A held lock is waited for only as long as the caller's context allows,
// so a pull's --timeout covers a pull queued behind another.
func TestWithLockEndsWithContext(t *testing.T) {
	s := tempStore(t)
	held, err := acquireFlock(context.Background(), s.lockPath())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*flockPoll)
	defer cancel()
	err = s.withLock(ctx, func() error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded while the lock is held", err)
	}
	held.Close()
	if err := s.withLock(context.Background(), func() error { return nil }); err != nil {
		t.Fatalf("lock released, err = %v", err)
	}
}

// A symlink at a managed cache parent would move the fill outside the store.
func TestCacheDirRejectsSymlinkedParent(t *testing.T) {
	good := "sha256:" + strings.Repeat("a", 64)
	for _, rel := range []string{cacheRootfs, filepath.Join(cacheRootfs, "sha256")} {
		s := tempStore(t)
		p := filepath.Join(s.root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.Symlink(t.TempDir(), p); err != nil {
			t.Fatal(err)
		}
		_, err := s.cacheDir(cacheRootfs, good)
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Errorf("%s: err = %v, want a symlink refusal", rel, err)
		}
	}
}
