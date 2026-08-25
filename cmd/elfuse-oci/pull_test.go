// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestNormalizeRef(t *testing.T) {
	sha := "sha256:" + strings.Repeat("0", 64)
	for _, tc := range []struct{ in, want string }{
		{"alpine", "docker.io/library/alpine:latest"},
		{"alpine:3", "docker.io/library/alpine:3"},
		{"foo/bar", "docker.io/foo/bar:latest"},
		{"docker.io/alpine", "docker.io/library/alpine:latest"},
		{"ghcr.io/foo/bar:v1", "ghcr.io/foo/bar:v1"},
		{"ghcr.io/foo/bar", "ghcr.io/foo/bar:latest"},
		{"localhost/foo", "localhost/foo:latest"},
		{"localhost:5000/foo", "localhost:5000/foo:latest"},
		{"alpine@" + sha, "docker.io/library/alpine@" + sha},
		{"registry.example.com:8443/a/b:t", "registry.example.com:8443/a/b:t"},
	} {
		got, err := normalizeRef(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("normalizeRef(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "Alpine", "alpine:", "a@sha256:short"} {
		if _, err := normalizeRef(bad); err == nil {
			t.Errorf("normalizeRef(%q) must fail", bad)
		}
	}
}

// A bare manifest states no platform, so its config is what a registry
// serving the wrong arch must be caught by.
func TestSelectManifestChecksSingleManifestPlatform(t *testing.T) {
	s, d := storeWithImage(t, "fix:1", testImage{})
	m := manifestOf(t, s, d)
	size := int64(len(mustJSON(t, m)))
	desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.Digest(d), Size: size}
	amd := platforms.OnlyStrict(ocispec.Platform{OS: "linux", Architecture: "amd64"})
	_, err := selectManifest(context.Background(), s.content, desc, amd)
	if !errors.Is(err, errdefs.ErrNotFound) {
		t.Fatalf("want ErrNotFound for platform mismatch, got %v", err)
	}
	arm := platforms.OnlyStrict(defaultPlatform)
	got, err := selectManifest(context.Background(), s.content, desc, arm)
	if err != nil || got.Digest.String() != d {
		t.Fatalf("matching platform select = %v, %v", got.Digest, err)
	}
}

// The matching index child is the pin whatever its position; an index
// with no match is ErrNotFound.
func TestSelectManifestPicksIndexChild(t *testing.T) {
	s, armDigest := storeWithImage(t, "idx:1", testImage{})
	amdDigest := pushTestImage(t, s, testImage{platform: ocispec.Platform{OS: "linux", Architecture: "amd64"}})
	child := func(d string, p ocispec.Platform) ocispec.Descriptor {
		m := manifestOf(t, s, d)
		return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.Digest(d),
			Size: int64(len(mustJSON(t, m))), Platform: &p}
	}
	idx := ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			child(amdDigest, ocispec.Platform{OS: "linux", Architecture: "amd64"}),
			child(armDigest, defaultPlatform),
		}}
	desc := pushBlob(t, s, ocispec.MediaTypeImageIndex, mustJSON(t, idx))
	got, err := selectManifest(context.Background(), s.content, desc, platforms.OnlyStrict(defaultPlatform))
	if err != nil || got.Digest.String() != armDigest {
		t.Fatalf("arm64 child = %v, %v; want %s", got.Digest, err, armDigest)
	}
	_, err = selectManifest(context.Background(), s.content, desc, platforms.OnlyStrict(ocispec.Platform{OS: "linux", Architecture: "s390x"}))
	if !errors.Is(err, errdefs.ErrNotFound) {
		t.Fatalf("want ErrNotFound for an index without the platform, got %v", err)
	}
}

// An index child that states no platform is checked against its config
// rather than pinned on the index's word: FilterPlatforms keeps such a
// child and LimitManifests only sorts it last, so it is picked whenever
// it is the sole survivor.
func TestSelectManifestChecksPlatformlessIndexChild(t *testing.T) {
	s, _ := storeWithImage(t, "idx:1", testImage{})
	amdDigest := pushTestImage(t, s, testImage{platform: ocispec.Platform{OS: "linux", Architecture: "amd64"}})
	m := manifestOf(t, s, amdDigest)
	idx := ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{{
			MediaType: ocispec.MediaTypeImageManifest, Digest: digest.Digest(amdDigest),
			Size: int64(len(mustJSON(t, m))),
		}}}
	desc := pushBlob(t, s, ocispec.MediaTypeImageIndex, mustJSON(t, idx))
	if _, err := selectManifest(context.Background(), s.content, desc, platforms.OnlyStrict(defaultPlatform)); !errors.Is(err, errdefs.ErrNotFound) {
		t.Fatalf("an amd64 child stating no platform must not pin for arm64, got %v", err)
	}
	amd := platforms.OnlyStrict(ocispec.Platform{OS: "linux", Architecture: "amd64"})
	got, err := selectManifest(context.Background(), s.content, desc, amd)
	if err != nil || got.Digest.String() != amdDigest {
		t.Fatalf("matching config platform = %v, %v; want %s", got.Digest, err, amdDigest)
	}
}

func TestPullFlagParsing(t *testing.T) {
	cf, timeout, ref, err := parseRefCommand("pull", pullFlagSet, []string{"--timeout", "5s", "--platform", "linux/amd64", "x:1"})
	if err != nil {
		t.Fatal(err)
	}
	if ref != "x:1" || timeout.String() != "5s" || cf.platform.Architecture != "amd64" {
		t.Fatalf("parsed = ref %q timeout %v platform %v", ref, timeout, cf.platform)
	}
	if _, _, _, err := parseRefCommand("pull", pullFlagSet, []string{"a", "b"}); err == nil {
		t.Fatal("two positionals must fail")
	}
}

// The network gate: a real pull lands a resolvable pin whose manifest,
// config, and layer blobs all exist on disk.
func TestPullRegistryRoundTrip(t *testing.T) {
	if os.Getenv("ELFUSE_OCI_NETTEST") == "" {
		t.Skip("set ELFUSE_OCI_NETTEST=1 to pull from a real registry")
	}
	s := tempStore(t)
	var err error
	captureOutput(t, func() {
		err = cmdPull([]string{"--store", s.root, "alpine:3"})
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.digestFor("alpine:3", defaultPlatform)
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.manifestFor(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	blobs := []string{d, m.Config.Digest.String()}
	for _, l := range m.Layers {
		blobs = append(blobs, l.Digest.String())
	}
	for _, b := range blobs {
		hex := strings.TrimPrefix(b, "sha256:")
		if _, err := os.Stat(filepath.Join(s.root, "blobs", "sha256", hex)); err != nil {
			t.Errorf("blob %s: %v", b, err)
		}
	}
}

// Only 0 means no limit; a negative --timeout is refused rather than read
// as unbounded.
func TestCmdPullRefusesNegativeTimeout(t *testing.T) {
	var err error
	captureOutput(t, func() { err = cmdPull([]string{"--timeout", "-1s", "x:1"}) })
	if err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("err = %v, want negative --timeout refusal", err)
	}
}
