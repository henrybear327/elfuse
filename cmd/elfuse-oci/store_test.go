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

// TestDigestForErrorKinds pins the distinction cmdRun's auto-pull relies on:
// a merely-absent ref is errNotPulled (triggers the pull), while a corrupt
// refs.json is a different error that must surface instead of being masked by
// a network pull.
func TestDigestForErrorKinds(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.digestFor("local:absent"); !errors.Is(err, errNotPulled) {
		t.Fatalf("missing ref err = %v, want errNotPulled", err)
	}
	if err := os.WriteFile(filepath.Join(s.root, "refs.json"), []byte("{corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.digestFor("local:absent")
	if err == nil || errors.Is(err, errNotPulled) {
		t.Fatalf("corrupt refs.json err = %v, must not be errNotPulled", err)
	}
}

// TestAddImageCorruptIndexSurfaces pins that addImage distinguishes "image
// not in the layout" from "layout index unreadable": appending into a corrupt
// store would mask the corruption behind a fresh descriptor.
func TestAddImageCorruptIndexSurfaces(t *testing.T) {
	s := openTestStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "index.json"), []byte("{corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.addImage("local:corrupt", tinyImage(t))
	if err == nil || !strings.Contains(err.Error(), "read layout index") {
		t.Fatalf("addImage with corrupt index.json err = %v, want read-layout-index error", err)
	}
	// The corrupt index must be left as-is for diagnosis, not clobbered by an
	// append.
	b, rerr := os.ReadFile(filepath.Join(s.root, "index.json"))
	if rerr != nil || string(b) != "{corrupt" {
		t.Fatalf("index.json after failed addImage = %q, err=%v; want untouched", b, rerr)
	}
}

// TestPinConcurrentWritersKeepAllEntries pins the store-lock behavior: N
// concurrent pin calls (as parallel `pull` processes would issue) must all
// survive into refs.json. Without the flock around the load-modify-save
// cycle, last-writer-wins drops entries.
func TestPinConcurrentWritersKeepAllEntries(t *testing.T) {
	s := openTestStore(t)
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- s.pin(fmt.Sprintf("local:ref%d", i), fmt.Sprintf("sha256:%064d", i))
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
// runs under the store lock. writeIfAbsent's stat-then-write is
// check-then-act: without the lock, a parallel first-use pull could rename an
// empty index.json over one the lock holder just populated, so openStore must
// block until the holder releases and then leave the populated index alone.
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
	// The lock holder commits a populated index, then releases. Bootstrap must
	// observe it and must not replace it with the empty scaffold.
	populated := `{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:` + strings.Repeat("a", 64) + `","size":1}]}`
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

func TestRepeatedStringFlag(t *testing.T) {
	var nilFlag *repeatedStringFlag
	if got := nilFlag.String(); got != "" {
		t.Fatalf("nil repeatedStringFlag String = %q, want empty", got)
	}

	var f repeatedStringFlag
	if err := f.Set("A=1"); err != nil {
		t.Fatal(err)
	}
	if err := f.Set("B=2"); err != nil {
		t.Fatal(err)
	}
	if got := f.String(); got != "A=1,B=2" {
		t.Fatalf("repeatedStringFlag String = %q, want A=1,B=2", got)
	}
}

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

func TestLoadPinsCorruptNullAndPinError(t *testing.T) {
	s := openTestStore(t)
	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{"malformed", "{", "corrupt refs.json"},
		{"null", "null", "expected object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(s.root, "refs.json"), []byte(tc.data), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := s.loadPins(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("loadPins err = %v, want %q", err, tc.want)
			}
			if err := s.pin("local:a", "sha256:"+strings.Repeat("1", 64)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("pin err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCacheKeyForDigestRejectsInvalidAndUnsupported(t *testing.T) {
	if _, err := cacheKeyForDigest("not-a-digest"); err == nil {
		t.Fatal("cacheKeyForDigest accepted malformed digest")
	}
	if _, err := defaultRootfsForDigest(t.TempDir(), "not-a-digest"); err == nil {
		t.Fatal("defaultRootfsForDigest accepted malformed digest")
	}
	unsupported := "sha512:" + strings.Repeat("1", 128)
	if _, err := cacheKeyForDigest(unsupported); err == nil {
		t.Fatalf("cacheKeyForDigest(%q) succeeded, want rejection", unsupported)
	}
}
