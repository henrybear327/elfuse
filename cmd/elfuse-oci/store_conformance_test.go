// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// TestStoreLayoutFiles asserts openStore creates the OCI image-layout
// scaffolding exactly: an oci-layout file with imageLayoutVersion 1.0.0, an
// index.json with an empty manifests array, and a blobs/sha256/ tree. This is
// the part of the OCI image-layout spec every conforming reader expects.
func TestStoreLayoutFiles(t *testing.T) {
	s := openTestStore(t)

	b, err := os.ReadFile(filepath.Join(s.root, "oci-layout"))
	if err != nil {
		t.Fatal(err)
	}
	var lay struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(b, &lay); err != nil {
		t.Fatalf("oci-layout is not JSON: %v (raw %q)", err, b)
	}
	if lay.Version != "1.0.0" {
		t.Errorf("imageLayoutVersion: got %q, want 1.0.0", lay.Version)
	}

	b, err = os.ReadFile(filepath.Join(s.root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Schema    int               `json:"schemaVersion"`
		Manifests []json.RawMessage `json:"manifests"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatalf("index.json is not JSON: %v", err)
	}
	if idx.Schema != 2 {
		t.Errorf("index schemaVersion: got %d, want 2", idx.Schema)
	}
	if len(idx.Manifests) != 0 {
		t.Errorf("fresh index has %d manifests, want 0", len(idx.Manifests))
	}

	if fi, err := os.Stat(filepath.Join(s.root, "blobs", "sha256")); err != nil || !fi.IsDir() {
		t.Errorf("blobs/sha256/ missing or not a directory: %v", err)
	}
}

// TestStoreLayoutRoundTrip stores a tiny image, then re-opens the layout with
// crane's own layout.FromPath reader (independent of our store.go write path)
// and asserts the manifest, config, and layer digests all round-trip. This
// is the offline OCI image-layout conformance signal: the on-disk bytes are
// parseable by the canonical go-containerregistry reader.
func TestStoreLayoutRoundTrip(t *testing.T) {
	s := openTestStore(t)
	img := tinyImage(t)
	wantManifest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	wantConfig, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	wantLayerDigests := make([]v1.Hash, len(layers))
	for i, l := range layers {
		d, err := l.Digest()
		if err != nil {
			t.Fatal(err)
		}
		wantLayerDigests[i] = d
	}

	digest, err := s.addImage("local:tiny", img)
	if err != nil {
		t.Fatal(err)
	}
	if digest != wantManifest.String() {
		t.Errorf("addImage digest: got %s, want %s", digest, wantManifest)
	}

	// Re-open the layout from disk with crane's reader, not our handle.
	p, err := layout.FromPath(s.root)
	if err != nil {
		t.Fatalf("layout.FromPath: %v (store is not a readable OCI layout)", err)
	}
	got, err := p.Image(wantManifest)
	if err != nil {
		t.Fatalf("re-opened layout cannot find manifest %s: %v", wantManifest, err)
	}
	gotManifest, err := got.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if gotManifest != wantManifest {
		t.Errorf("manifest digest: got %s, want %s", gotManifest, wantManifest)
	}
	gotConfig, err := got.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	if gotConfig != wantConfig {
		t.Errorf("config digest: got %s, want %s", gotConfig, wantConfig)
	}
	gotLayers, err := got.Layers()
	if err != nil {
		t.Fatal(err)
	}
	if len(gotLayers) != len(wantLayerDigests) {
		t.Fatalf("layer count: got %d, want %d", len(gotLayers), len(wantLayerDigests))
	}
	for i, l := range gotLayers {
		d, err := l.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if d != wantLayerDigests[i] {
			t.Errorf("layer %d digest: got %s, want %s", i, d, wantLayerDigests[i])
		}
	}

	for _, h := range append([]v1.Hash{wantManifest, wantConfig}, wantLayerDigests...) {
		p := filepath.Join(s.root, "blobs", h.Algorithm, h.Hex)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("blob %s missing on disk: %v", h, err)
		}
	}

	gotDigest, err := s.digestFor("local:tiny")
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != wantManifest.String() {
		t.Errorf("pin: got %s, want %s", gotDigest, wantManifest)
	}
}

// TestStoreInteropPullRoundTrip pulls a real image and asserts the store
// round-trips through crane's independent reader, exactly like the offline
// round-trip but with a registry-fetched image. Gated behind ELFUSE_OCI_NETTEST
// so `go test` stays green offline; CI enables it on the Linux conformance job.
func TestStoreInteropPullRoundTrip(t *testing.T) {
	if os.Getenv("ELFUSE_OCI_NETTEST") != "1" {
		t.Skip("set ELFUSE_OCI_NETTEST=1 to pull real images")
	}
	ref := "alpine:3"
	cf := commonFlags{platform: defaultPlatform}

	s := openTestStore(t)
	if err := pullImage(cf, s, ref); err != nil {
		t.Fatalf("pull %s failed with ELFUSE_OCI_NETTEST=1: %v", ref, err)
	}

	digestStr, err := s.digestFor(ref)
	if err != nil {
		t.Fatal(err)
	}
	wantManifest, err := v1.NewHash(digestStr)
	if err != nil {
		t.Fatal(err)
	}

	p, err := layout.FromPath(s.root)
	if err != nil {
		t.Fatalf("layout.FromPath: %v", err)
	}
	got, err := p.Image(wantManifest)
	if err != nil {
		t.Fatalf("crane reader cannot find manifest %s: %v", wantManifest, err)
	}
	gotManifest, err := got.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if gotManifest != wantManifest {
		t.Errorf("manifest digest: got %s, want %s", gotManifest, wantManifest)
	}
	if _, err := got.ConfigFile(); err != nil {
		t.Errorf("ConfigFile: %v", err)
	}
	layers, err := got.Layers()
	if err != nil || len(layers) == 0 {
		t.Fatalf("layers: %v (got %d)", err, len(layers))
	}
	for _, l := range layers {
		if _, err := l.Digest(); err != nil {
			t.Errorf("layer digest: %v", err)
		}
	}
}

// TestStoreDedupOnRePull asserts that adding the same image twice does not
// accumulate a second manifest descriptor in the layout index (addImage dedups
// by digest), while the ref pin still resolves to that digest.
func TestStoreDedupOnRePull(t *testing.T) {
	s := openTestStore(t)
	img := tinyImage(t)
	want, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:tiny", img); err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:tiny", img); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(s.root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatalf("index.json unmarshal: %v", err)
	}
	count := 0
	for _, m := range idx.Manifests {
		if m.Digest == want.String() {
			count++
		}
	}
	if count != 1 {
		t.Errorf("manifest descriptor for %s appears %d times, want 1 (dedup)", want, count)
	}

	got, err := s.digestFor("local:tiny")
	if err != nil {
		t.Fatalf("digestFor: %v", err)
	}
	if got != want.String() {
		t.Errorf("pin: got %s, want %s", got, want)
	}
}

// TestStoreLayoutRoundTripAfterDescriptorRemoval asserts the index.json our
// removeManifestDescriptor hand-marshals stays parseable by the canonical
// go-containerregistry reader: after rmi drops one of two images, the reader
// finds the survivor and no longer finds the removed manifest. This guards the
// switch from the layout package's RemoveDescriptors to our own durable
// atomic write.
func TestStoreLayoutRoundTripAfterDescriptorRemoval(t *testing.T) {
	s := openTestStore(t)
	imgA := buildImage(t, []string{"/a"})
	imgB := buildImage(t, []string{"/b"})
	digestA, err := imgA.Digest()
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := imgB.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:a", imgA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:b", imgB); err != nil {
		t.Fatal(err)
	}

	if _, err := s.rmi("local:a", false); err != nil {
		t.Fatalf("rmi local:a: %v", err)
	}

	// Re-open with crane's reader, independent of our write path.
	p, err := layout.FromPath(s.root)
	if err != nil {
		t.Fatalf("layout.FromPath after descriptor removal: %v (index.json not canonical)", err)
	}
	ii, err := p.ImageIndex()
	if err != nil {
		t.Fatal(err)
	}
	im, err := ii.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range im.Manifests {
		if d.Digest == digestA {
			t.Fatalf("removed manifest %s still present in index.json", digestA)
		}
	}
	if _, err := p.Image(digestB); err != nil {
		t.Fatalf("surviving manifest %s not readable after removal: %v", digestB, err)
	}
}

// TestWriteFileDurableAtomicAndLeavesPriorOnFailure pins writeFileDurable's two
// guarantees: a successful write replaces the file with exactly the new bytes,
// and a failed write (a read-only directory blocks the temp create) leaves any
// prior file untouched rather than truncating it.
func TestWriteFileDurableAtomicAndLeavesPriorOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := writeFileDurable(path, []byte("first"), 0o644); err != nil {
		t.Fatalf("writeFileDurable first: %v", err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "first" {
		t.Fatalf("after first write = %q, err=%v; want first", b, err)
	}
	if err := writeFileDurable(path, []byte("second"), 0o644); err != nil {
		t.Fatalf("writeFileDurable second: %v", err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "second" {
		t.Fatalf("after second write = %q, err=%v; want second", b, err)
	}

	if os.Getuid() == 0 {
		t.Skip("running as root: a read-only dir does not block the temp create")
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := writeFileDurable(path, []byte("third"), 0o644); err == nil {
		t.Fatal("writeFileDurable into read-only dir succeeded, want failure")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "second" {
		t.Fatalf("after failed write = %q, err=%v; want prior content second", b, err)
	}
}
