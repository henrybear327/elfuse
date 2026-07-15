// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

func firstLayerDigest(t *testing.T, img v1.Image) v1.Hash {
	t.Helper()
	ls, err := img.Layers()
	if err != nil || len(ls) == 0 {
		t.Fatalf("layers: %v (n=%d)", err, len(ls))
	}
	d, err := ls[0].Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func indexManifestCount(t *testing.T, root string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Manifests []json.RawMessage `json:"manifests"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatalf("index.json unmarshal: %v", err)
	}
	return len(idx.Manifests)
}

func rootfsForDigest(t *testing.T, s *store, digest string) string {
	t.Helper()
	rootfs, err := defaultRootfsForDigest(s.root, digest)
	if err != nil {
		t.Fatal(err)
	}
	return rootfs
}

func rootfsForImage(t *testing.T, s *store, img v1.Image) string {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return rootfsForDigest(t, s, d.String())
}

// TestPruneReclaimsRepulledTagPriorImage pins #14: re-pulling a mutable tag to
// a new digest must not leak the prior image. Reachability GC roots at the pin
// set, and gc reconciles index.json to it, so after the tag moves A->B a prune
// removes A's orphaned descriptor and its unique blobs (manifest, config) while
// keeping the layer blob B still shares, and B stays intact.
func TestPruneReclaimsRepulledTagPriorImage(t *testing.T) {
	s := openTestStore(t)
	imgA := buildImage(t, []string{"/a"})
	imgB := buildImage(t, []string{"/b"})

	manifestA, err := imgA.Digest()
	if err != nil {
		t.Fatal(err)
	}
	configA, err := imgA.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	sharedLayer := firstLayerDigest(t, imgA)
	if got := firstLayerDigest(t, imgB); got != sharedLayer {
		t.Fatalf("test images do not share a layer: A=%s B=%s", sharedLayer, got)
	}

	if _, err := s.addImage("local:tag", imgA); err != nil {
		t.Fatal(err)
	}
	digestB, err := s.addImage("local:tag", imgB) // repin tag A->B; A now orphaned
	if err != nil {
		t.Fatal(err)
	}
	if n := indexManifestCount(t, s.root); n != 2 {
		t.Fatalf("index has %d descriptors after repull, want 2 (A leaked, B live)", n)
	}

	if err := cmdPrune([]string{"--store", s.root}); err != nil {
		t.Fatalf("prune: %v", err)
	}

	if n := indexManifestCount(t, s.root); n != 1 {
		t.Fatalf("index has %d descriptors after prune, want 1 (A reclaimed)", n)
	}
	for _, gone := range []v1.Hash{manifestA, configA} {
		if _, err := os.Stat(blobPath(s.root, gone.String())); !os.IsNotExist(err) {
			t.Errorf("orphaned blob %s still present after prune: %v", gone, err)
		}
	}
	if _, err := os.Stat(blobPath(s.root, sharedLayer.String())); err != nil {
		t.Errorf("shared layer %s reclaimed although B still references it: %v", sharedLayer, err)
	}
	got, err := s.digestFor("local:tag")
	if err != nil || got != digestB {
		t.Fatalf("tag resolves to %q err=%v; want B %s", got, err, digestB)
	}
	if _, err := s.image("local:tag"); err != nil {
		t.Fatalf("image B unreadable after prune: %v", err)
	}
}

// --- list -------------------------------------------------------------------

func TestListEmpty(t *testing.T) {
	s := openTestStore(t)
	var buf bytes.Buffer
	if err := list(&buf, s, false); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("human list of empty store produced output %q, want none", buf.String())
	}
	var jbuf bytes.Buffer
	if err := list(&jbuf, s, true); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(jbuf.String()) != "[]" {
		t.Errorf("json list of empty store = %q, want []", jbuf.String())
	}
}

func TestListShape(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:a", buildImage(t, []string{"/hello"})); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := list(&buf, s, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"local:a", "linux/arm64"} {
		if !strings.Contains(out, want) {
			t.Errorf("human list missing %q in:\n%s", want, out)
		}
	}

	var jbuf bytes.Buffer
	if err := list(&jbuf, s, true); err != nil {
		t.Fatal(err)
	}
	var entries []listEntry
	if err := json.Unmarshal(jbuf.Bytes(), &entries); err != nil {
		t.Fatalf("json list unmarshal: %v (raw %q)", err, jbuf.String())
	}
	if len(entries) != 1 || entries[0].Ref != "local:a" {
		t.Fatalf("json list entries = %+v, want one local:a", entries)
	}
	e := entries[0]
	if !strings.HasPrefix(e.Digest, "sha256:") {
		t.Errorf("json digest = %q, want sha256: prefix", e.Digest)
	}
	if e.Platform != "linux/arm64" {
		t.Errorf("json platform = %q, want linux/arm64", e.Platform)
	}
	if e.Layers != 1 {
		t.Errorf("json layers = %d, want 1", e.Layers)
	}
	if e.Size <= 0 {
		t.Errorf("json size = %d, want > 0 (compressed layer size)", e.Size)
	}
}

func TestListCorruptConfigErrors(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	config, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(blobPath(s.root, config.String())); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err = list(&buf, s, false)
	if err == nil || !strings.Contains(err.Error(), "list: local:a: config") {
		t.Fatalf("list err = %v, want local:a config error", err)
	}
}

func TestListMultipleRefsSorted(t *testing.T) {
	s := openTestStore(t)
	for _, ref := range []string{"local:b", "local:a"} {
		if _, err := s.addImage(ref, buildImage(t, []string{ref})); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := list(&buf, s, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if i, j := strings.Index(out, "local:a"), strings.Index(out, "local:b"); i < 0 || j < 0 || i > j {
		t.Errorf("list not sorted by ref:\n%s", out)
	}
}

// --- rmi --------------------------------------------------------------------

func TestRmiDropsPinAndBlobs(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	manifest, _ := img.Digest()
	config, _ := img.ConfigName()
	layer := firstLayerDigest(t, img)
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}

	if _, err := s.rmi("local:a", false); err != nil {
		t.Fatalf("rmi: %v", err)
	}
	if _, err := s.digestFor("local:a"); err == nil {
		t.Error("digestFor after rmi succeeded, want not-pulled error")
	}
	for _, d := range []string{manifest.String(), config.String(), layer.String()} {
		if _, err := os.Stat(blobPath(s.root, d)); !os.IsNotExist(err) {
			t.Errorf("blob %s after rmi: %v, want IsNotExist", d, err)
		}
	}
	if n := indexManifestCount(t, s.root); n != 0 {
		t.Errorf("index.json after rmi has %d manifest descriptors, want 0", n)
	}
}

func TestRmiByRefDropsStaleTempBlob(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	layer := firstLayerDigest(t, img)
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	stale := writeStaleTempBlob(t, s.root, layer.String())

	rep, err := s.rmi("local:a", false)
	if err != nil {
		t.Fatalf("rmi by ref with stale temp blob: %v", err)
	}
	if !slices.Contains(rep.Blobs, stale) {
		t.Fatalf("rmi report blobs = %v, want stale temp blob %s", rep.Blobs, stale)
	}
	if _, err := os.Stat(blobPath(s.root, stale)); !os.IsNotExist(err) {
		t.Fatalf("stale temp blob after rmi by ref: %v, want IsNotExist", err)
	}
	if _, err := s.digestFor("local:a"); err == nil {
		t.Fatal("local:a pin still present after rmi by ref")
	}
}

func TestRmiKeepsSharedBlobs(t *testing.T) {
	s := openTestStore(t)
	imgA := buildImage(t, []string{"/a"})
	imgB := buildImage(t, []string{"/b"})
	sharedLayer := firstLayerDigest(t, imgA) // same content -> same digest as imgB's layer
	if _, err := s.addImage("local:a", imgA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:b", imgB); err != nil {
		t.Fatal(err)
	}

	if _, err := s.rmi("local:a", false); err != nil {
		t.Fatalf("rmi local:a: %v", err)
	}
	if _, err := os.Stat(blobPath(s.root, sharedLayer.String())); err != nil {
		t.Errorf("shared layer blob after rmi local:a: %v, want present (still reachable via local:b)", err)
	}
	if _, err := s.digestFor("local:b"); err != nil {
		t.Fatalf("local:b pin lost after rmi local:a: %v", err)
	}
	if img, err := s.image("local:b"); err != nil {
		t.Errorf("s.image(local:b) after rmi local:a: %v", err)
	} else if ls, _ := img.Layers(); len(ls) != 1 {
		t.Errorf("local:b layers after rmi local:a = %d, want 1", len(ls))
	}
}

func TestRmiKeepsSameDigestPinnedByOtherRef(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	manifest, _ := img.Digest()
	config, _ := img.ConfigName()
	layer := firstLayerDigest(t, img)
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:b", img); err != nil {
		t.Fatal(err)
	}
	if n := indexManifestCount(t, s.root); n != 1 {
		t.Fatalf("index manifest count before rmi = %d, want 1", n)
	}

	rep, err := s.rmi("local:a", false)
	if err != nil {
		t.Fatalf("rmi local:a: %v", err)
	}
	if len(rep.Blobs) != 0 || rep.Bytes != 0 {
		t.Fatalf("rmi local:a report = %+v, want no blobs removed", rep)
	}
	if _, err := s.digestFor("local:a"); err == nil {
		t.Error("local:a pin still present after rmi, want gone")
	}
	if got, err := s.digestFor("local:b"); err != nil {
		t.Fatalf("local:b pin lost after rmi local:a: %v", err)
	} else if got != manifest.String() {
		t.Fatalf("local:b digest = %s, want %s", got, manifest)
	}
	if n := indexManifestCount(t, s.root); n != 1 {
		t.Fatalf("index manifest count after rmi local:a = %d, want 1", n)
	}
	for _, d := range []string{manifest.String(), config.String(), layer.String()} {
		if _, err := os.Stat(blobPath(s.root, d)); err != nil {
			t.Errorf("blob %s after rmi local:a: %v, want present", d, err)
		}
	}
	if _, err := s.image("local:b"); err != nil {
		t.Fatalf("s.image(local:b) after rmi local:a: %v", err)
	}
}

func TestRmiAbsentRefErrors(t *testing.T) {
	s := openTestStore(t)
	_, err := s.rmi("local:never", false)
	if err == nil || !strings.Contains(err.Error(), "not pulled") {
		t.Errorf("rmi absent ref err = %v, want an error mentioning \"not pulled\"", err)
	}
}

func TestRmiByDigestDropsStaleTempBlob(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	manifest, _ := img.Digest()
	layer := firstLayerDigest(t, img)
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	stale := writeStaleTempBlob(t, s.root, layer.String())

	rep, err := s.rmi(shortDigest(manifest.String()), false)
	if err != nil {
		t.Fatalf("rmi by digest with stale temp blob: %v", err)
	}
	if rep.Ref != "local:a" {
		t.Fatalf("rmi report ref = %q, want local:a", rep.Ref)
	}
	if !slices.Contains(rep.Blobs, stale) {
		t.Fatalf("rmi report blobs = %v, want stale temp blob %s", rep.Blobs, stale)
	}
	if _, err := os.Stat(blobPath(s.root, stale)); !os.IsNotExist(err) {
		t.Fatalf("stale temp blob after rmi by digest: %v, want IsNotExist", err)
	}
}

func TestRmiAcceptsDigestFromList(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target func(string) string
	}{
		{"short hex", shortDigest},
		{"full digest", func(d string) string { return d }},
		{"qualified prefix", func(d string) string { return "sha256:" + shortDigest(d) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			img := buildImage(t, []string{"/hello"})
			manifest, _ := img.Digest()
			if _, err := s.addImage("local:a", img); err != nil {
				t.Fatal(err)
			}

			rep, err := s.rmi(tc.target(manifest.String()), false)
			if err != nil {
				t.Fatalf("rmi by digest: %v", err)
			}
			if rep.Ref != "local:a" {
				t.Fatalf("rmi report ref = %q, want local:a", rep.Ref)
			}
			if _, err := s.digestFor("local:a"); err == nil {
				t.Fatal("local:a pin still present after digest rmi")
			}
			if _, err := os.Stat(blobPath(s.root, manifest.String())); !os.IsNotExist(err) {
				t.Fatalf("manifest blob after digest rmi: %v, want IsNotExist", err)
			}
		})
	}
}

func TestCmdRmiAcceptsDigestPrintedByList(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:a", buildImage(t, []string{"/hello"})); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := list(&buf, s, false); err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(buf.String())
	if len(fields) < 7 {
		t.Fatalf("list output has too few fields:\n%s", buf.String())
	}
	listedDigest := fields[6]

	if err := cmdRmi([]string{"--store", s.root, listedDigest}); err != nil {
		t.Fatalf("cmdRmi by listed digest %q: %v", listedDigest, err)
	}
	if _, err := s.digestFor("local:a"); err == nil {
		t.Fatal("local:a pin still present after cmdRmi by listed digest")
	}
}

func TestRmiDigestPrefixAmbiguous(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	manifest, _ := img.Digest()
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:b", img); err != nil {
		t.Fatal(err)
	}

	_, err := s.rmi(shortDigest(manifest.String()), false)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") || !strings.Contains(err.Error(), "local:a, local:b") {
		t.Fatalf("rmi ambiguous digest err = %v, want both refs listed", err)
	}
	if _, err := s.digestFor("local:a"); err != nil {
		t.Fatalf("local:a pin lost after ambiguous rmi: %v", err)
	}
	if _, err := s.digestFor("local:b"); err != nil {
		t.Fatalf("local:b pin lost after ambiguous rmi: %v", err)
	}
}

func TestRmiKeepsCacheForSameDigestPinnedByOtherRef(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:b", img); err != nil {
		t.Fatal(err)
	}
	rootfs := rootfsForImage(t, s, img)
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := s.rmi("local:a", false); err != nil {
		t.Fatalf("rmi local:a with shared cache: %v", err)
	}
	if _, err := os.Stat(rootfs); err != nil {
		t.Fatalf("shared digest rootfs after rmi local:a: %v, want present", err)
	}
	if _, err := s.digestFor("local:b"); err != nil {
		t.Fatalf("local:b pin lost after rmi local:a: %v", err)
	}

	// Removing the last ref reclaims the now-unshared cache with the image.
	rep, err := s.rmi("local:b", false)
	if err != nil {
		t.Fatalf("rmi final shared-cache ref: %v", err)
	}
	if !rep.CacheDropped {
		t.Error("rmi last shared-cache ref did not report dropping the cache")
	}
	if _, err := os.Stat(rootfs); !os.IsNotExist(err) {
		t.Fatalf("shared digest rootfs after final rmi: %v, want removed", err)
	}
}

func TestRmiForceDropsCache(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	rootfs := rootfsForImage(t, s, img)
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := s.rmi("local:a", true); err != nil {
		t.Fatalf("rmi --force: %v", err)
	}
	if _, err := os.Stat(rootfs); !os.IsNotExist(err) {
		t.Errorf("rootfs cache after rmi --force: %v, want IsNotExist", err)
	}
	if _, err := s.digestFor("local:a"); err == nil {
		t.Error("pin still present after rmi --force, want gone")
	}
}

// TestRmiDropsColdCacheWithoutForce pins the fixed behavior: a plain rmi
// reclaims a cold unpacked cache as part of removing the image, so the natural
// run -> rmi lifecycle needs no --force and leaves no orphan cache.
func TestRmiDropsColdCacheWithoutForce(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	rootfs := rootfsForImage(t, s, img)
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}

	rep, err := s.rmi("local:a", false)
	if err != nil {
		t.Fatalf("rmi cold cache without --force: %v", err)
	}
	if !rep.CacheDropped {
		t.Error("rmi did not report dropping the cold cache")
	}
	if _, err := os.Stat(rootfs); !os.IsNotExist(err) {
		t.Errorf("cold cache after rmi: %v, want removed", err)
	}
	if _, err := s.digestFor("local:a"); err == nil {
		t.Error("pin present after rmi, want gone")
	}
}

func TestDigestCachePathChangesWhenRefDigestChanges(t *testing.T) {
	s := openTestStore(t)
	ref := "local:tag"

	imgA := buildImage(t, []string{"/a"})
	if _, err := s.addImage(ref, imgA); err != nil {
		t.Fatal(err)
	}
	rootfsA := rootfsForImage(t, s, imgA)

	imgB := buildImage(t, []string{"/b"})
	if _, err := s.addImage(ref, imgB); err != nil {
		t.Fatal(err)
	}
	rootfsB := rootfsForImage(t, s, imgB)

	if rootfsA == rootfsB {
		t.Fatalf("digest-keyed rootfs path did not change across repull: %s", rootfsA)
	}
	if got := filepath.Dir(rootfsB); filepath.Base(got) != "sha256" {
		t.Fatalf("rootfs path %s not under rootfs/sha256/<hex>", rootfsB)
	}
}

func TestDigestCachePathsAvoidRefEncodingCollisions(t *testing.T) {
	s := openTestStore(t)
	refA := "local/a:b"
	refB := "local:a/b"
	if legacyCacheNameForRef(refA) != legacyCacheNameForRef(refB) {
		t.Fatalf("test refs no longer collide under legacy encoding: %q vs %q", refA, refB)
	}

	imgA := buildImage(t, []string{"/a"})
	imgB := buildImage(t, []string{"/b"})
	if _, err := s.addImage(refA, imgA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage(refB, imgB); err != nil {
		t.Fatal(err)
	}

	rootfsA := rootfsForImage(t, s, imgA)
	rootfsB := rootfsForImage(t, s, imgB)
	if rootfsA == rootfsB {
		t.Fatalf("digest-keyed refs collided at %s", rootfsA)
	}
}

// --- prune ------------------------------------------------------------------

// writeOrphanBlob writes an unreferenced file under blobs/sha256/ named with a
// valid sha256 digest so the local GC treats it as an unreachable blob.
func writeOrphanBlob(t *testing.T, root, content string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(content))
	hex := hex.EncodeToString(sum[:])
	p := blobPath(root, hex)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + hex
}

func writeStaleTempBlob(t *testing.T, root, baseDigest string) string {
	t.Helper()
	name := strings.TrimPrefix(baseDigest, "sha256:") + "1072211852"
	p := blobPath(root, name)
	if err := os.WriteFile(p, []byte("stale temp blob"), 0o644); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + name
}

func TestPruneSweepsOrphanBlob(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	manifest, _ := img.Digest()
	config, _ := img.ConfigName()
	layer := firstLayerDigest(t, img)
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	orphan := writeOrphanBlob(t, s.root, "orphan-bytes")

	rep, err := s.gc(false)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if len(rep.Blobs) != 1 || rep.Blobs[0] != orphan {
		t.Errorf("gc removed = %v, want [%s]", rep.Blobs, orphan)
	}
	if _, err := os.Stat(blobPath(s.root, orphan)); !os.IsNotExist(err) {
		t.Errorf("orphan blob after prune: %v, want gone", err)
	}
	for _, d := range []string{manifest.String(), config.String(), layer.String()} {
		if _, err := os.Stat(blobPath(s.root, d)); err != nil {
			t.Errorf("referenced blob %s lost after prune: %v", d, err)
		}
	}
}

func TestPruneSweepsOrphanAndStaleTempBlobs(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	layer := firstLayerDigest(t, img)
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	orphan := writeOrphanBlob(t, s.root, "orphan-bytes")
	stale := writeStaleTempBlob(t, s.root, layer.String())

	rep, err := s.gc(false)
	if err != nil {
		t.Fatalf("gc with stale temp blob: %v", err)
	}
	for _, want := range []string{orphan, stale} {
		if !slices.Contains(rep.Blobs, want) {
			t.Fatalf("gc removed = %v, want %s", rep.Blobs, want)
		}
		if _, err := os.Stat(blobPath(s.root, want)); !os.IsNotExist(err) {
			t.Fatalf("blob %s after prune: %v, want gone", want, err)
		}
	}
	if _, err := os.Stat(blobPath(s.root, layer.String())); err != nil {
		t.Fatalf("live layer blob after prune: %v, want present", err)
	}
}

func TestPruneDryRunDeletesNothing(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:a", buildImage(t, []string{"/hello"})); err != nil {
		t.Fatal(err)
	}
	orphan := writeOrphanBlob(t, s.root, "orphan-bytes")

	rep, err := s.gc(true)
	if err != nil {
		t.Fatalf("gc --dry-run: %v", err)
	}
	if len(rep.Blobs) != 1 || rep.Blobs[0] != orphan {
		t.Errorf("dry-run gc reported = %v, want [%s]", rep.Blobs, orphan)
	}
	if _, err := os.Stat(blobPath(s.root, orphan)); err != nil {
		t.Errorf("orphan blob deleted under --dry-run: %v, want present", err)
	}
}

func TestPruneDryRunKeepsStaleTempBlob(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	layer := firstLayerDigest(t, img)
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	stale := writeStaleTempBlob(t, s.root, layer.String())

	rep, err := s.gc(true)
	if err != nil {
		t.Fatalf("gc --dry-run with stale temp blob: %v", err)
	}
	if !slices.Contains(rep.Blobs, stale) {
		t.Fatalf("dry-run gc reported = %v, want stale temp blob %s", rep.Blobs, stale)
	}
	if _, err := os.Stat(blobPath(s.root, stale)); err != nil {
		t.Fatalf("stale temp blob deleted under --dry-run: %v, want present", err)
	}
}

func TestPruneCacheDropsUnpulledRootfs(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:a", buildImage(t, []string{"/hello"})); err != nil {
		t.Fatal(err)
	}
	// Legacy cache for an unpulled ref "local:b", an orphan cache under the
	// digest-keyed layout.
	orphanCache := legacyRootfsForRef(s.root, "local:b")
	if err := os.MkdirAll(orphanCache, 0o755); err != nil {
		t.Fatal(err)
	}

	rep, err := s.pruneCaches(pruneOpts{cache: true})
	if err != nil {
		t.Fatalf("pruneCaches: %v", err)
	}
	if len(rep.CacheDirs) != 1 || rep.CacheDirs[0] != orphanCache {
		t.Errorf("pruneCaches dropped = %v, want [%s]", rep.CacheDirs, orphanCache)
	}
	if _, err := os.Stat(orphanCache); !os.IsNotExist(err) {
		t.Errorf("orphan rootfs cache after prune --cache: %v, want gone", err)
	}
	if _, err := s.digestFor("local:a"); err != nil {
		t.Errorf("local:a pin lost after prune --cache: %v", err)
	}
}

func TestPruneCacheAllDropsPulledRootfs(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	liveCache := rootfsForImage(t, s, img)
	if err := os.MkdirAll(liveCache, 0o755); err != nil {
		t.Fatal(err)
	}

	rep, err := s.pruneCaches(pruneOpts{cache: true, all: true})
	if err != nil {
		t.Fatalf("pruneCaches --all: %v", err)
	}
	if len(rep.CacheDirs) != 1 || rep.CacheDirs[0] != liveCache {
		t.Errorf("pruneCaches --all dropped = %v, want [%s]", rep.CacheDirs, liveCache)
	}
	if _, err := os.Stat(liveCache); !os.IsNotExist(err) {
		t.Errorf("live rootfs cache after prune --cache --all: %v, want gone", err)
	}
	// --all drops the cache only; the store (pin + blobs) is untouched.
	if _, err := s.digestFor("local:a"); err != nil {
		t.Errorf("local:a pin lost after prune --cache --all: %v", err)
	}
}

func TestRmiThenPruneIdempotent(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:a", buildImage(t, []string{"/hello"})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.rmi("local:a", false); err != nil {
		t.Fatalf("rmi: %v", err)
	}
	rep, err := s.gc(false)
	if err != nil {
		t.Fatalf("gc after rmi: %v", err)
	}
	if len(rep.Blobs) != 0 {
		t.Errorf("gc after rmi removed %v, want nothing (already reclaimed)", rep.Blobs)
	}
}

// --- sweepable clone detection ----------------------------------------------

// TestListSweepableClonesSkipsKeepMarkerAndNonClones pins the reap set the
// bundle sweep uses once it holds run.lock exclusively: every run-<pid>-<ns>
// clone WITHOUT a keep marker plus any rootfs.tmp-* unpack leftover, and
// nothing else. Pids are irrelevant now; the exclusive lock already proves
// no run is live.
func TestListSweepableClonesSkipsKeepMarkerAndNonClones(t *testing.T) {
	dir := t.TempDir()
	reapClone := filepath.Join(dir, "run-1234-1")
	keepClone := filepath.Join(dir, "run-5678-2")
	tmpUnpack := filepath.Join(dir, "rootfs.tmp-abcd")
	rootfs := filepath.Join(dir, "rootfs")
	for _, p := range []string{reapClone, keepClone, tmpUnpack, rootfs} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeKeepMarker(keepClone); err != nil {
		t.Fatal(err)
	}

	got := listSweepableClones(dir)
	want := map[string]bool{reapClone: true, tmpUnpack: true}
	if len(got) != len(want) {
		t.Fatalf("listSweepableClones = %v, want %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("listSweepableClones included %q, want only %v", g, want)
		}
	}

	// The read-only lister removes nothing.
	for _, p := range []string{reapClone, keepClone, tmpUnpack, rootfs} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("listSweepableClones removed %s, want read-only: %v", p, err)
		}
	}

	// reapSweepableClones removes exactly the sweepable set, keeping the
	// marked clone, the base rootfs, and the keep marker's clone dir.
	reaped := reapSweepableClones(dir)
	if len(reaped) != 2 {
		t.Fatalf("reapSweepableClones = %v, want 2 entries", reaped)
	}
	if _, err := os.Stat(reapClone); !os.IsNotExist(err) {
		t.Errorf("unmarked clone not reaped: %v", err)
	}
	if _, err := os.Stat(tmpUnpack); !os.IsNotExist(err) {
		t.Errorf("unpack leftover not reaped: %v", err)
	}
	if _, err := os.Stat(keepClone); err != nil {
		t.Errorf("kept clone was reaped, want preserved: %v", err)
	}
	if _, err := os.Stat(rootfs); err != nil {
		t.Errorf("base rootfs was reaped, want left alone: %v", err)
	}
}

// TestListSweepableClonesPreservesOnMarkerStatError pins the fail-safe: if the
// keep-marker stat returns a transient non-ENOENT error (here EACCES from an
// unreadable keep directory), the clone is preserved rather than reaped;
// reaping a --keep clone on a flaky read would be data loss.
func TestListSweepableClonesPreservesOnMarkerStatError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not bind as root")
	}
	dir := t.TempDir()
	clone := filepath.Join(dir, "run-1-1")
	if err := os.MkdirAll(clone, 0o755); err != nil {
		t.Fatal(err)
	}
	// 0o000 on the keep dir makes os.Stat(.elfuse-keep/run-1-1) fail with
	// EACCES (cannot traverse .elfuse-keep), not ENOENT, while dir itself stays
	// readable so the clone is still discovered.
	if err := os.MkdirAll(keepDirPath(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keepDirPath(dir), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keepDirPath(dir), 0o755) })

	if got := listSweepableClones(dir); len(got) != 0 {
		t.Fatalf("listSweepableClones = %v, want empty (fail safe on marker stat error)", got)
	}
}

// TestListSweepableClonesReapsImageShippedKeepFile pins #10/S9: a clone whose
// own contents include /.elfuse-keep (an image that ships that path, or a guest
// that wrote it) is NOT preserved. The keep record lives in the mount-root keep
// directory, outside every guest's view, so only elfuse-oci's --keep can
// set it; forged in-clone files are ignored and the clone is reaped.
func TestListSweepableClonesReapsImageShippedKeepFile(t *testing.T) {
	dir := t.TempDir()
	clone := filepath.Join(dir, "run-7-7")
	if err := os.MkdirAll(clone, 0o755); err != nil {
		t.Fatal(err)
	}
	// The image (or guest) planted /.elfuse-keep inside the clone.
	if err := os.WriteFile(filepath.Join(clone, ".elfuse-keep"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	got := listSweepableClones(dir)
	if len(got) != 1 || got[0] != clone {
		t.Fatalf("listSweepableClones = %v, want the clone reapable despite in-clone /.elfuse-keep", got)
	}

	// A genuine --keep record in the mount-root keep dir does preserve it.
	if err := writeKeepMarker(clone); err != nil {
		t.Fatal(err)
	}
	if got := listSweepableClones(dir); len(got) != 0 {
		t.Fatalf("listSweepableClones = %v, want kept clone skipped after writeKeepMarker", got)
	}
}

// TestCSBundleBusy pins the read-only busy probe used by prune --dry-run: a
// bundle whose run.lock is held (a live run) reports busy; an idle one does
// not.
func TestCSBundleBusy(t *testing.T) {
	bundle := t.TempDir()
	if csBundleBusy(bundle) {
		t.Fatal("csBundleBusy(idle) = true, want false")
	}
	hold, err := acquireFlock(runLockPath(bundle), syscall.LOCK_SH)
	if err != nil {
		t.Fatal(err)
	}
	if !csBundleBusy(bundle) {
		t.Fatal("csBundleBusy(live run) = false, want true")
	}
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	if csBundleBusy(bundle) {
		t.Fatal("csBundleBusy after release = true, want false")
	}
}

func TestListMissingImage(t *testing.T) {
	s := openTestStore(t)
	missingDigest := "sha256:" + strings.Repeat("9", 64)
	if err := s.savePins(refPins{"missing": missingDigest}); err != nil {
		t.Fatal(err)
	}
	if err := list(&bytes.Buffer{}, s, false); err == nil || !strings.Contains(err.Error(), "list: missing: image") {
		t.Fatalf("list missing image err = %v, want image error", err)
	}
}

func TestShortDigest(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"short hex passthrough", "abcdef", "abcdef"},
		{"exactly twelve", "123456789012", "123456789012"},
		{"truncated to twelve", "123456789012345", "123456789012"},
		{"sha256 prefix stripped and truncated", "sha256:abcdef1234567890abcdef00", "abcdef123456"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shortDigest(tc.in); got != tc.want {
				t.Fatalf("shortDigest(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestListShowsPlatformVariant pins that a variant-qualified platform is not
// truncated to os/arch in list output.
func TestListShowsPlatformVariant(t *testing.T) {
	s := openTestStore(t)
	img, err := mutate.ConfigFile(buildImage(t, []string{"/hello"}), &v1.ConfigFile{
		Architecture: "arm64",
		OS:           "linux",
		Variant:      "v8",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:variant", img); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := list(&buf, s, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "linux/arm64/v8") {
		t.Fatalf("list output %q missing linux/arm64/v8", buf.String())
	}
}

// --- plain-rootfs run lock ---------------------------------------------------

func TestRootfsCacheBusy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	if rootfsCacheBusy(dir) {
		t.Fatal("rootfsCacheBusy(no lock file) = true, want false")
	}
	hold, err := acquireRootfsRunLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rootfsCacheBusy(dir) {
		t.Fatal("rootfsCacheBusy(live run) = false, want true")
	}
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	if rootfsCacheBusy(dir) {
		t.Fatal("rootfsCacheBusy after release = true, want false")
	}
}

// TestPruneCacheHonorsRootfsRunLock pins the busy semantics of the plain
// cache sweep: a digest cache whose run lock is held by a live run survives
// prune --cache --all and is never advertised by a dry run; an idle cache
// (including one with a stale lock file left by a dead run) is reclaimed,
// lock file included.
func TestPruneCacheHonorsRootfsRunLock(t *testing.T) {
	cases := []struct {
		name      string
		holdLock  bool
		staleLock bool
		dryRun    bool
		wantGone  bool
		wantInRep bool
	}{
		{name: "live run skipped", holdLock: true},
		{name: "live run hidden from dry-run", holdLock: true, dryRun: true},
		{name: "idle reclaimed", wantGone: true, wantInRep: true},
		{name: "stale lock file reclaimed", staleLock: true, wantGone: true, wantInRep: true},
		{name: "idle dry-run reported only", dryRun: true, wantInRep: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			img := buildImage(t, []string{"/hello"})
			if _, err := s.addImage("local:a", img); err != nil {
				t.Fatal(err)
			}
			cache := rootfsForImage(t, s, img)
			if err := os.MkdirAll(cache, 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.holdLock {
				hold, err := acquireRootfsRunLock(cache)
				if err != nil {
					t.Fatal(err)
				}
				defer hold.Close()
			}
			if tc.staleLock {
				if err := os.WriteFile(rootfsRunLockPath(cache), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}

			rep, err := s.pruneCaches(pruneOpts{cache: true, all: true, dryRun: tc.dryRun})
			if err != nil {
				t.Fatalf("pruneCaches: %v", err)
			}

			inRep := slices.Contains(rep.CacheDirs, cache)
			if inRep != tc.wantInRep {
				t.Errorf("reported = %v, want %v (dirs %v)", inRep, tc.wantInRep, rep.CacheDirs)
			}
			_, statErr := os.Stat(cache)
			gone := os.IsNotExist(statErr)
			wantGone := tc.wantGone && !tc.dryRun
			if gone != wantGone {
				t.Errorf("cache gone = %v, want %v (stat err %v)", gone, wantGone, statErr)
			}
			if wantGone {
				if _, err := os.Lstat(rootfsRunLockPath(cache)); !os.IsNotExist(err) {
					t.Errorf("lock file after reclaim: %v, want gone", err)
				}
			}
		})
	}
}

// TestPruneCacheHonorsLockForStagingDir pins that the sweep guards a
// staging dir (<hex>.tmp-<random>, unpackImage's pre-rename workspace) by
// the DIGEST's run lock, which the unpacker holds for the whole unpack: a
// mid-flight unpack survives prune --cache --all and never appears in a dry
// run, while a crashed unpack's leftover (digest lock free) is reclaimed.
func TestPruneCacheHonorsLockForStagingDir(t *testing.T) {
	cases := []struct {
		name      string
		holdLock  bool
		dryRun    bool
		wantGone  bool
		wantInRep bool
	}{
		{name: "live unpack skipped", holdLock: true},
		{name: "live unpack hidden from dry-run", holdLock: true, dryRun: true},
		{name: "crashed leftover reclaimed", wantGone: true, wantInRep: true},
		{name: "crashed leftover dry-run reported only", dryRun: true, wantInRep: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			img := buildImage(t, []string{"/hello"})
			if _, err := s.addImage("local:a", img); err != nil {
				t.Fatal(err)
			}
			cache := rootfsForImage(t, s, img)
			staging := cache + rootfsStagingSuffix + "123456"
			if err := os.MkdirAll(staging, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(staging, "f"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.holdLock {
				// The digest's lock, exactly what a live unpacker holds; a
				// lock named after the staging dir itself never exists.
				hold, err := acquireRootfsRunLock(cache)
				if err != nil {
					t.Fatal(err)
				}
				defer hold.Close()
			}

			rep, err := s.pruneCaches(pruneOpts{cache: true, all: true, dryRun: tc.dryRun})
			if err != nil {
				t.Fatalf("pruneCaches: %v", err)
			}

			inRep := slices.Contains(rep.CacheDirs, staging)
			if inRep != tc.wantInRep {
				t.Errorf("reported = %v, want %v (dirs %v)", inRep, tc.wantInRep, rep.CacheDirs)
			}
			_, statErr := os.Stat(staging)
			gone := os.IsNotExist(statErr)
			if gone != tc.wantGone {
				t.Errorf("staging gone = %v, want %v (stat err %v)", gone, tc.wantGone, statErr)
			}
		})
	}
}

// TestRemoveRootfsCacheMissingDirRespectsLock pins the lock-first rule for
// a cache dir that is already gone: a staging dir vanishes exactly when its
// unpack renames it into place, and that holder still owns the digest lock,
// so removal must refuse rather than unlink the lock out from under it.
// With no holder the stale lock file is swept, and a path with no store
// structure at all is a plain no-op.
func TestRemoveRootfsCacheMissingDirRespectsLock(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "sha256", strings.Repeat("ab", 32))
	hold, err := acquireRootfsRunLock(cache)
	if err != nil {
		t.Fatal(err)
	}
	staging := cache + rootfsStagingSuffix + "123456"

	if err := removeRootfsCache(staging); !errors.Is(err, errCacheBusy) {
		t.Fatalf("removeRootfsCache(vanished staging, lock held) = %v, want errCacheBusy", err)
	}
	if _, err := os.Lstat(rootfsRunLockPath(cache)); err != nil {
		t.Errorf("digest lock file unlinked by refused removal: %v", err)
	}

	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeRootfsCache(staging); err != nil {
		t.Fatalf("removeRootfsCache(vanished staging, idle) = %v", err)
	}
	if _, err := os.Lstat(rootfsRunLockPath(cache)); !os.IsNotExist(err) {
		t.Errorf("stale digest lock survived idle removal: %v", err)
	}

	if err := removeRootfsCache(filepath.Join(t.TempDir(), "nope", "sha256", "feed")); err != nil {
		t.Fatalf("removeRootfsCache(no store structure) = %v, want nil", err)
	}
}

// TestRmiRefusesLiveRootfsRun pins rmi's fail-closed rule for the plain
// cache: even --force refuses while a live run holds the per-digest lock,
// and the pin survives the refusal; once the run exits the same rmi
// succeeds and reclaims cache and lock file.
func TestRmiRefusesLiveRootfsRun(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}
	cache := rootfsForImage(t, s, img)
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	hold, err := acquireRootfsRunLock(cache)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.rmi("local:a", true); err == nil ||
		!strings.Contains(err.Error(), "in use by a live run") {
		t.Fatalf("rmi under live run err = %v, want live-run refusal", err)
	}
	if _, err := s.digestFor("local:a"); err != nil {
		t.Errorf("pin lost after refused rmi: %v", err)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Errorf("cache damaged after refused rmi: %v", err)
	}

	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.rmi("local:a", true); err != nil {
		t.Fatalf("rmi after run exit: %v", err)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Errorf("cache after rmi: %v, want gone", err)
	}
	if _, err := os.Lstat(rootfsRunLockPath(cache)); !os.IsNotExist(err) {
		t.Errorf("lock file after rmi: %v, want gone", err)
	}
}
