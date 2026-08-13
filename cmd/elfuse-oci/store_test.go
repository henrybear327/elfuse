// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestDigestForErrorKinds pins that a missing ref is errNotPulled while
// a corrupt refs.json is not; see errNotPulled.
func TestDigestForErrorKinds(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.digestFor("local:absent", defaultPlatform); !errors.Is(err, errNotPulled) {
		t.Fatalf("missing ref err = %v, want errNotPulled", err)
	}
	if err := os.WriteFile(filepath.Join(s.root, "refs.json"), []byte("{corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.digestFor("local:absent", defaultPlatform)
	if err == nil || errors.Is(err, errNotPulled) {
		t.Fatalf("corrupt refs.json err = %v, must not be errNotPulled", err)
	}
}

// TestAddImageCorruptIndexSurfaces pins that addImage surfaces a corrupt
// layout index instead of appending into it; see hasImageLocked.
func TestAddImageCorruptIndexSurfaces(t *testing.T) {
	s := openTestStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "index.json"), []byte("{corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.addImage("local:corrupt", defaultPlatform, tinyImage(t))
	if err == nil || !strings.Contains(err.Error(), "read layout index") {
		t.Fatalf("addImage with corrupt index.json err = %v, want read-layout-index error", err)
	}
	b, rerr := os.ReadFile(filepath.Join(s.root, "index.json"))
	if rerr != nil || string(b) != "{corrupt" {
		t.Fatalf("index.json after failed addImage = %q, err=%v; want untouched", b, rerr)
	}
}

// TestAddImageHealsPartialConfigBlob pins that appendImageLocked writes
// config and manifest blobs through writeFileDurable: a truncated blob
// left at its final path by an interrupted pull is replaced, where the
// layout package's existence check would have accepted it as complete.
func TestAddImageHealsPartialConfigBlob(t *testing.T) {
	s := openTestStore(t)
	img := tinyImage(t)
	ch, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	p := blobPath(s.root, ch.String())
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	seedImage(t, s, "local:heal", img)
	raw, err := img.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("config blob after addImage = %q, want the full config %q", got, raw)
	}
}

// TestAddImageHealsLostLayerBlob pins that blob writes are not gated on
// index presence: with the image already in index.json, a re-add restores
// a layer blob that was deleted and one that was truncated, where a
// presence-gated append would skip the write and fail every later pull on
// the same damaged blob.
func TestAddImageHealsLostLayerBlob(t *testing.T) {
	for _, damage := range []struct {
		name  string
		apply func(t *testing.T, p string)
	}{
		{"deleted", func(t *testing.T, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncated", func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(damage.name, func(t *testing.T) {
			s := openTestStore(t)
			img := tinyImage(t)
			seedImage(t, s, "local:heal-layer", img)
			layers, err := img.Layers()
			if err != nil {
				t.Fatal(err)
			}
			lh, err := layers[0].Digest()
			if err != nil {
				t.Fatal(err)
			}
			p := blobPath(s.root, lh.String())
			want, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			damage.apply(t, p)
			seedImage(t, s, "local:heal-layer", img)
			got, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("layer blob after re-add: %v", err)
			}
			if string(got) != string(want) {
				t.Fatalf("layer blob after re-add = %d bytes, want the original %d", len(got), len(want))
			}
		})
	}
}

// TestPinsPerPlatform pins that one ref holds a pin per platform: a pull
// for a second platform must not replace the first platform's pin, and
// digestFor resolves each platform to its own manifest.
func TestPinsPerPlatform(t *testing.T) {
	s := openTestStore(t)
	arm := buildImage(t, []string{"/arm"})
	amd := buildImage(t, []string{"/amd"})
	amdPlat := Platform{OS: "linux", Arch: "amd64"}
	armDigest, err := s.addImage("local:multi", defaultPlatform, arm)
	if err != nil {
		t.Fatal(err)
	}
	amdDigest, err := s.addImage("local:multi", amdPlat, amd)
	if err != nil {
		t.Fatal(err)
	}
	if armDigest == amdDigest {
		t.Fatal("test images collapsed to one digest; the pins cannot disagree")
	}
	got, err := s.digestFor("local:multi", defaultPlatform)
	if err != nil || got != armDigest {
		t.Fatalf("digestFor arm64 = %q, %v; want %q", got, err, armDigest)
	}
	got, err = s.digestFor("local:multi", amdPlat)
	if err != nil || got != amdDigest {
		t.Fatalf("digestFor amd64 = %q, %v; want %q", got, err, amdDigest)
	}
}

// TestAddImageSetsDescriptorPlatform pins that the appended index
// descriptor carries the image's platform (partial.Descriptor leaves it
// nil), so index.json can tell one ref's platform variants apart.
func TestAddImageSetsDescriptorPlatform(t *testing.T) {
	s := openTestStore(t)
	seedImage(t, s, "local:desc", tinyImage(t))
	ii, err := s.path.ImageIndex()
	if err != nil {
		t.Fatal(err)
	}
	im, err := ii.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(im.Manifests) != 1 || im.Manifests[0].Platform == nil {
		t.Fatalf("index descriptors = %+v, want one with Platform set", im.Manifests)
	}
	p := im.Manifests[0].Platform
	if p.OS != "linux" || p.Architecture != "arm64" {
		t.Fatalf("descriptor platform = %s/%s, want linux/arm64", p.OS, p.Architecture)
	}
}

// TestAddImageSecondImageKeepsFirst pins the store-owned index append:
// a second image's descriptor lands beside the first, and both stay
// readable through their pins.
func TestAddImageSecondImageKeepsFirst(t *testing.T) {
	s := openTestStore(t)
	seedImage(t, s, "local:one", buildImage(t, []string{"/one"}))
	seedImage(t, s, "local:two", buildImage(t, []string{"/two"}))
	ii, err := s.path.ImageIndex()
	if err != nil {
		t.Fatal(err)
	}
	im, err := ii.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(im.Manifests) != 2 {
		t.Fatalf("index has %d manifests, want 2", len(im.Manifests))
	}
	for _, ref := range []string{"local:one", "local:two"} {
		img, err := s.image(ref, defaultPlatform)
		if err != nil {
			t.Fatalf("image(%q): %v", ref, err)
		}
		if _, err := img.ConfigFile(); err != nil {
			t.Fatalf("image(%q) config: %v", ref, err)
		}
	}
}

// TestPinConcurrentWritersKeepAllEntries pins that concurrent pin calls
// all survive into refs.json (see store.lock for the flock rationale).
func TestPinConcurrentWritersKeepAllEntries(t *testing.T) {
	s := openTestStore(t)
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- s.pin(fmt.Sprintf("local:ref%d", i), defaultPlatform.String(), fmt.Sprintf("sha256:%064d", i))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	pins, err := s.loadPins()
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != n {
		t.Fatalf("refs.json has %d pins after %d concurrent writers, want %d", len(pins), n, n)
	}
}

// TestOpenStoreBootstrapWaitsForStoreLock pins that openStore's bootstrap
// blocks on the store lock and leaves a concurrently populated
// index.json alone; see writeIfAbsent.
func TestOpenStoreBootstrapWaitsForStoreLock(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// Hold the store lock as a concurrent pull's metadata write would.
	lockFile, err := os.OpenFile(filepath.Join(root, ".lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := openStore(root)
		done <- err
	}()
	select {
	case <-done:
		t.Fatal("openStore finished while the store lock was held; bootstrap must serialize with metadata writers")
	case <-time.After(100 * time.Millisecond):
	}
	populated := `{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"` + fakeDigest('a') + `","size":1}]}`
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(populated), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != populated {
		t.Fatalf("index.json after bootstrap = %q, want the populated index left untouched", b)
	}
}

// TestDefaultStoreFromEnvAndResolveStore pins the resolution order:
// $ELFUSE_OCI_STORE, else ~/.local/share/elfuse/oci; resolveStore
// creates the directory and rejects a non-directory path.
func TestDefaultStoreFromEnvAndResolveStore(t *testing.T) {
	want := filepath.Join(t.TempDir(), "store")
	t.Setenv("ELFUSE_OCI_STORE", want)
	got, err := defaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("defaultStore = %q, want %q", got, want)
	}

	var cf commonFlags
	if err := cf.resolveStore(); err != nil {
		t.Fatalf("resolveStore: %v", err)
	}
	if cf.store != want {
		t.Fatalf("resolved store = %q, want %q", cf.store, want)
	}
	if fi, err := os.Stat(want); err != nil || !fi.IsDir() {
		t.Fatalf("resolved store dir = %v, err=%v; want directory", fi, err)
	}

	fileStore := filepath.Join(t.TempDir(), "store-file")
	if err := os.WriteFile(fileStore, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	cf = commonFlags{store: fileStore}
	if err := cf.resolveStore(); err == nil {
		t.Fatal("resolveStore on file path succeeded, want error")
	}

	home := t.TempDir()
	t.Setenv("ELFUSE_OCI_STORE", "")
	t.Setenv("HOME", home)
	got, err = defaultStore()
	if err != nil {
		t.Fatal(err)
	}
	want = filepath.Join(home, ".local", "share", "elfuse", "oci")
	if got != want {
		t.Fatalf("defaultStore without env = %q, want %q", got, want)
	}
}

// TestOpenStoreAndWriteIfAbsentErrorCases pins that openStore rejects a
// non-directory root and writeIfAbsent leaves an existing file
// untouched.
func TestOpenStoreAndWriteIfAbsentErrorCases(t *testing.T) {
	rootFile := filepath.Join(t.TempDir(), "store-file")
	if err := os.WriteFile(rootFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(rootFile); err == nil {
		t.Fatal("openStore on file path succeeded, want error")
	}

	p := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeIfAbsent(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old" {
		t.Fatalf("writeIfAbsent overwrote existing file with %q, want old", b)
	}
}

// TestWriteFileDurableAtomicAndLeavesPriorOnFailure pins that a
// successful write replaces the file with exactly the new bytes and a
// failed write leaves any prior file untouched.
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

// Regression guard for writeFileDurable's deferred os.Remove: a directory
// at the destination fails the rename after the temp is fully written, a
// branch the read-only-dir case cannot reach; deleting the defer turns
// this red.
func TestWriteFileDurableLeavesNoTempOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.MkdirAll(filepath.Join(path, "x"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := writeFileDurable(path, []byte("data"), 0o644); err == nil {
		t.Fatal("writeFileDurable onto a non-empty directory succeeded, want error")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "f" {
		t.Fatalf("rename failure left litter: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(path, "x")); err != nil {
		t.Fatalf("destination directory disturbed by the failed write: %v", err)
	}
}

// TestLoadPinsCorruptNullAndPinError pins fail-closed pin-table reads: a
// malformed, JSON-null, or pre-platform flat-shape refs.json errors from
// loadPins and pin; read as an empty table, the next savePins would erase
// every pin.
func TestLoadPinsCorruptNullAndPinError(t *testing.T) {
	s := openTestStore(t)
	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{"malformed", "{", "corrupt refs.json"},
		{"null", "null", "expected object"},
		{"flat digest value", `{"local:a": "sha256:aaa"}`, "corrupt refs.json"},
		{"null platform table", `{"local:a": null}`, "expected object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(s.root, "refs.json"), []byte(tc.data), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := s.loadPins(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("loadPins err = %v, want %q", err, tc.want)
			}
			if err := s.pin("local:a", defaultPlatform.String(), fakeDigest('1')); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("pin err = %v, want %q", err, tc.want)
			}
		})
	}
}
