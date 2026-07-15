// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

// TestRmiKeepsPinWhenDescriptorRemovalFails pins the rmi write ordering:
// index.json must be updated before the pin is dropped from refs.json. In the
// reverse order a failure between the writes strands the manifest: the ref
// no longer resolves while the descriptor keeps all blobs live, and prune
// never removes descriptors. With the correct order the pin survives the
// failure and a retried rmi completes.
func TestRmiKeepsPinWhenDescriptorRemovalFails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: a read-only store dir cannot induce the write failure")
	}
	s := openTestStore(t)
	if _, err := s.addImage("local:stuck", buildImage(t, []string{"/a"})); err != nil {
		t.Fatal(err)
	}
	// index.json is now written atomically (temp + rename), so a read-only
	// index.json no longer blocks the write: a rename replaces the file
	// regardless of its mode. Make the store directory read-only instead, so
	// the descriptor removal's temp create fails before refs.json is touched.
	if err := os.Chmod(s.root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(s.root, 0o755) })

	if _, err := s.rmi("local:stuck", false); err == nil {
		t.Fatal("rmi succeeded although the store directory is read-only")
	}
	pins, err := s.loadPins()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pins["local:stuck"]; !ok {
		t.Fatal("pin dropped although descriptor removal failed; image is stranded")
	}

	if err := os.Chmod(s.root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.rmi("local:stuck", false); err != nil {
		t.Fatalf("retried rmi after transient failure: %v", err)
	}
	pins, err = s.loadPins()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pins["local:stuck"]; ok {
		t.Fatal("pin still present after successful retried rmi")
	}
}

// TestGCReclaimsOrphanKeepsLive exercises store.gc directly (the lifecycle tests
// otherwise only reach it through rmi/prune): an unreferenced blob is reclaimed
// while a still-pinned image's own manifest/config/layers survive.
func TestGCReclaimsOrphanKeepsLive(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:a", buildImage(t, []string{"/a"})); err != nil {
		t.Fatal(err)
	}
	orphan := writeOrphanBlob(t, s.root, "gc-direct-orphan")

	rep, err := s.gc(false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rep.Blobs, orphan) {
		t.Fatalf("gc did not report orphan %s; blobs=%v", orphan, rep.Blobs)
	}
	if _, err := os.Stat(blobPath(s.root, orphan)); !os.IsNotExist(err) {
		t.Fatalf("orphan blob still present after gc: %v", err)
	}
	if _, err := s.image("local:a"); err != nil {
		t.Fatalf("live image unreadable after gc (live blobs reclaimed): %v", err)
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

func TestInvalidPinnedDigestErrors(t *testing.T) {
	s := openTestStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "refs.json"), []byte(`{"bad":"not-a-digest"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.image("bad"); err == nil {
		t.Fatal("image with invalid pinned digest succeeded, want error")
	}
	var buf bytes.Buffer
	if err := list(&buf, s, false); err == nil || !strings.Contains(err.Error(), `digest "not-a-digest"`) {
		t.Fatalf("list err = %v, want invalid digest error", err)
	}
	if _, err := s.liveCacheKeys(); err == nil {
		t.Fatal("liveCacheKeys with invalid pinned digest succeeded, want error")
	}
}

func TestRemoveManifestDescriptorAndGCErrors(t *testing.T) {
	s := openTestStore(t)
	if err := s.removeManifestDescriptor("not-a-digest"); err == nil {
		t.Fatal("removeManifestDescriptor invalid digest succeeded, want error")
	}

	// Pin a ref so gc's descriptor reconciliation and reachability both have to
	// read the (now corrupt) index.json rather than short-circuiting on an
	// empty pin set.
	if _, err := s.addImage("local:a", buildImage(t, []string{"/a"})); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.root, "index.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.gc(false); err == nil || !strings.Contains(err.Error(), "index") {
		t.Fatalf("gc corrupt index err = %v, want an index parse error", err)
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

func TestPruneRootfsCachesKeepsLiveDropsOrphanAndDryRun(t *testing.T) {
	s := &store{root: t.TempDir()}
	liveHex := strings.Repeat("a", 64)
	orphanHex := strings.Repeat("b", 64)
	liveDir := filepath.Join(s.root, "rootfs", "sha256", liveHex)
	orphanDir := filepath.Join(s.root, "rootfs", "sha256", orphanHex)
	for _, dir := range []string{liveDir, orphanDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "file"), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.root, "rootfs", "sha256", "not-a-dir"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	live := map[string]bool{filepath.Join("sha256", liveHex): true}
	rep, err := pruneRootfsCaches(s, live, pruneOpts{cache: true, dryRun: true})
	if err != nil {
		t.Fatalf("dry-run pruneRootfsCaches: %v", err)
	}
	if len(rep.CacheDirs) != 1 || rep.CacheDirs[0] != orphanDir {
		t.Fatalf("dry-run cache dirs = %v, want [%s]", rep.CacheDirs, orphanDir)
	}
	if _, err := os.Stat(orphanDir); err != nil {
		t.Fatalf("dry-run removed orphan cache: %v", err)
	}

	rep, err = pruneRootfsCaches(s, live, pruneOpts{cache: true})
	if err != nil {
		t.Fatalf("pruneRootfsCaches: %v", err)
	}
	if len(rep.CacheDirs) != 1 || rep.CacheDirs[0] != orphanDir {
		t.Fatalf("cache dirs = %v, want [%s]", rep.CacheDirs, orphanDir)
	}
	if _, err := os.Stat(orphanDir); !os.IsNotExist(err) {
		t.Fatalf("orphan cache after prune: %v, want IsNotExist", err)
	}
	if _, err := os.Stat(liveDir); err != nil {
		t.Fatalf("live cache removed: %v", err)
	}
}

func TestPruneRootfsCachesMissingRootAndDiskUsageFallback(t *testing.T) {
	s := &store{root: t.TempDir()}
	rep, err := pruneRootfsCaches(s, nil, pruneOpts{cache: true})
	if err != nil {
		t.Fatalf("missing rootfs prune: %v", err)
	}
	if len(rep.CacheDirs) != 0 || rep.Bytes != 0 {
		t.Fatalf("missing rootfs report = %+v, want empty", rep)
	}

	if got := diskUsage(fakeFileInfo{size: 123}); got != 123 {
		t.Fatalf("diskUsage fallback = %d, want logical size 123", got)
	}
}

func TestPruneCachesErrorsOnInvalidLivePin(t *testing.T) {
	s := openTestStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "refs.json"), []byte(`{"bad":"not-a-digest"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pruneCaches(pruneOpts{cache: true}); err == nil {
		t.Fatal("pruneCaches with invalid live pin succeeded, want error")
	}
}

func TestDigestPrefix(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"abcdef123456", "abcdef123456", true},
		{"sha256:ABCDEF123456", "abcdef123456", true},
		{"abcdef12345", "", false},
		{strings.Repeat("a", 65), "", false},
		{"sha512:" + strings.Repeat("a", 64), "", false},
		{"not-hex-12345", "", false},
	}
	for _, tc := range cases {
		got, ok := digestPrefix(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("digestPrefix(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestResolvePinnedTarget(t *testing.T) {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	digestAmbiguous := "sha256:" + strings.Repeat("a", 12) + strings.Repeat("c", 52)
	base := refPins{
		"local:a": digestA,
		"local:b": digestB,
	}
	ambiguous := refPins{
		"local:a":         digestA,
		"local:b":         digestB,
		"local:ambiguous": digestAmbiguous,
	}

	cases := []struct {
		name       string
		pins       refPins
		target     string
		wantRef    string
		wantDigest string
		wantErr    string // when set, expect an error containing this and ignore wantRef/wantDigest
	}{
		{name: "exact ref", pins: base, target: "local:a", wantRef: "local:a", wantDigest: digestA},
		{name: "unique prefix", pins: base, target: strings.Repeat("b", 12), wantRef: "local:b", wantDigest: digestB},
		{name: "uppercase prefix", pins: base, target: "sha256:" + strings.Repeat("B", 12), wantRef: "local:b", wantDigest: digestB},
		{name: "missing digest", pins: base, target: strings.Repeat("d", 12), wantErr: "not pulled"},
		{name: "invalid target", pins: base, target: "not-a-ref", wantErr: "not pulled"},
		{name: "ambiguous prefix", pins: ambiguous, target: strings.Repeat("a", 12), wantErr: "ambiguous"},
		{name: "invalid pinned digest", pins: refPins{"bad": "not-a-digest"}, target: strings.Repeat("e", 12), wantErr: "pinned digest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref, digest, err := resolvePinnedTarget(tc.pins, tc.target)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || ref != tc.wantRef || digest != tc.wantDigest {
				t.Fatalf("resolve = ref=%q digest=%q err=%v, want %s %s", ref, digest, err, tc.wantRef, tc.wantDigest)
			}
		})
	}

	// The ambiguous case must list the colliding refs in sorted order.
	if _, _, err := resolvePinnedTarget(ambiguous, strings.Repeat("a", 12)); err == nil ||
		!strings.Contains(err.Error(), "local:a, local:ambiguous") {
		t.Fatalf("ambiguous err = %v, want sorted ambiguous refs", err)
	}
}

func TestRmiByDigestPrefixReportsResolvedRef(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	digest, err := s.addImage("local:a", img)
	if err != nil {
		t.Fatal(err)
	}
	prefix := strings.TrimPrefix(digest, "sha256:")[:12]
	rep, err := s.rmi(prefix, false)
	if err != nil {
		t.Fatalf("rmi by prefix: %v", err)
	}
	if rep.Ref != "local:a" {
		t.Fatalf("rmi report ref = %q, want local:a", rep.Ref)
	}
	if _, err := s.digestFor("local:a"); err == nil {
		t.Fatal("local:a pin still present after rmi by digest prefix")
	}

	s = openTestStore(t)
	digest, err = s.addImage("local:a", img)
	if err != nil {
		t.Fatal(err)
	}
	prefix = strings.TrimPrefix(digest, "sha256:")[:12]
	_, stderr, err := captureOutput(t, func() error {
		return cmdRmi([]string{"--store", s.root, prefix})
	})
	if err != nil {
		t.Fatalf("cmdRmi by prefix: %v", err)
	}
	if !strings.Contains(stderr, "Removed local:a:") || strings.Contains(stderr, "Removed "+prefix+":") {
		t.Fatalf("cmdRmi stderr = %q, want resolved ref in summary", stderr)
	}
}

type fakeFileInfo struct {
	size int64
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return 0o644 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }
