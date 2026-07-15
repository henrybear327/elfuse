// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1"
)

func withFakeCranePull(t *testing.T, fn func(string, ...crane.Option) (v1.Image, error)) {
	t.Helper()
	old := cranePull
	cranePull = fn
	t.Cleanup(func() { cranePull = old })
}

func withFakeExecElfuse(t *testing.T, fn func(string, *runSpec, *flockFile) error) {
	t.Helper()
	old := execElfuseForRun
	execElfuseForRun = fn
	t.Cleanup(func() { execElfuseForRun = old })
}

func TestCmdPullPinsImageOffline(t *testing.T) {
	root := t.TempDir()
	img := tinyImage(t)
	wantDigest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	var gotRef string
	var gotOptions int
	withFakeCranePull(t, func(ref string, opts ...crane.Option) (v1.Image, error) {
		gotRef = ref
		gotOptions = len(opts)
		return img, nil
	})

	stdout, stderr, err := captureOutput(t, func() error {
		return cmdPull([]string{"--store", root, "--platform", "linux/amd64", "local:tiny"})
	})
	if err != nil {
		t.Fatalf("cmdPull: %v", err)
	}
	if stdout != "" {
		t.Fatalf("cmdPull stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "Pulled local:tiny -> "+wantDigest.String()) {
		t.Fatalf("cmdPull stderr = %q, want pull summary", stderr)
	}
	if gotRef != "local:tiny" || gotOptions != 1 {
		t.Fatalf("fake crane.Pull got ref=%q options=%d, want local:tiny and platform option", gotRef, gotOptions)
	}

	s, err := openStore(root)
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, err := s.digestFor("local:tiny")
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != wantDigest.String() {
		t.Fatalf("pin digest = %s, want %s", gotDigest, wantDigest)
	}
}

func TestCmdPullWrapsPullError(t *testing.T) {
	root := t.TempDir()
	withFakeCranePull(t, func(ref string, opts ...crane.Option) (v1.Image, error) {
		return nil, errors.New("registry unavailable")
	})

	_, _, err := captureOutput(t, func() error {
		return cmdPull([]string{"--store", root, "local:missing"})
	})
	if err == nil || !strings.Contains(err.Error(), "pull local:missing") || !strings.Contains(err.Error(), "registry unavailable") {
		t.Fatalf("cmdPull error = %v, want wrapped pull error", err)
	}
}

func TestCmdListInspectRmiAndPruneWrappers(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/hello"})
	manifest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := captureOutput(t, func() error {
		return cmdList([]string{"--store", s.root})
	})
	if err != nil {
		t.Fatalf("cmdList: %v", err)
	}
	if stderr != "" || !strings.Contains(stdout, "local:a") || !strings.Contains(stdout, "linux/arm64") {
		t.Fatalf("cmdList stdout=%q stderr=%q, want list row", stdout, stderr)
	}
	listedDigest := shortDigest(manifest.String())
	if !strings.Contains(stdout, listedDigest) {
		t.Fatalf("cmdList stdout=%q, want digest %s", stdout, listedDigest)
	}

	stdout, stderr, err = captureOutput(t, func() error {
		return cmdInspect([]string{"--store", s.root, "--json", "local:a"})
	})
	if err != nil {
		t.Fatalf("cmdInspect --json: %v", err)
	}
	// The raw config blob (compact, as stored), not a re-marshal: vendor
	// extension fields must survive inspect --json.
	if stderr != "" || !strings.Contains(stdout, `"architecture":"arm64"`) || !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("cmdInspect stdout=%q stderr=%q, want raw config JSON with trailing newline", stdout, stderr)
	}

	orphan := writeOrphanBlob(t, s.root, "command-prune-orphan")
	stdout, stderr, err = captureOutput(t, func() error {
		return cmdPrune([]string{"--store", s.root, "--dry-run"})
	})
	if err != nil {
		t.Fatalf("cmdPrune --dry-run: %v", err)
	}
	if stdout != "" || !strings.Contains(stderr, "Would reclaim: 1 blob(s)") || !strings.Contains(stderr, orphan) {
		t.Fatalf("cmdPrune dry-run stdout=%q stderr=%q, want dry-run summary", stdout, stderr)
	}
	if _, err := os.Stat(blobPath(s.root, orphan)); err != nil {
		t.Fatalf("dry-run removed orphan blob: %v", err)
	}

	stdout, stderr, err = captureOutput(t, func() error {
		return cmdPrune([]string{"--store", s.root})
	})
	if err != nil {
		t.Fatalf("cmdPrune: %v", err)
	}
	if stdout != "" || !strings.Contains(stderr, "Reclaimed: 1 blob(s)") {
		t.Fatalf("cmdPrune stdout=%q stderr=%q, want reclaim summary", stdout, stderr)
	}
	if _, err := os.Stat(blobPath(s.root, orphan)); !os.IsNotExist(err) {
		t.Fatalf("orphan blob after prune: %v, want IsNotExist", err)
	}

	stdout, stderr, err = captureOutput(t, func() error {
		return cmdRmi([]string{"--store", s.root, listedDigest})
	})
	if err != nil {
		t.Fatalf("cmdRmi: %v", err)
	}
	if stdout != "" || !strings.Contains(stderr, "Removed local:a:") {
		t.Fatalf("cmdRmi stdout=%q stderr=%q, want removal summary", stdout, stderr)
	}
	if _, err := s.digestFor("local:a"); err == nil {
		t.Fatal("local:a pin still present after cmdRmi")
	}
}

func TestCmdUnpackWrapperExplicitAndDefaultRootfs(t *testing.T) {
	s := openTestStore(t)
	img := tinyImage(t)
	digest, err := s.addImage("local:tiny", img)
	if err != nil {
		t.Fatal(err)
	}

	explicit := filepath.Join(t.TempDir(), "explicit-rootfs")
	stdout, stderr, err := captureOutput(t, func() error {
		return cmdUnpack([]string{"--store", s.root, "--rootfs", explicit, "local:tiny"})
	})
	if err != nil {
		t.Fatalf("cmdUnpack explicit: %v", err)
	}
	if stdout != "" || !strings.Contains(stderr, "Unpacking local:tiny -> "+explicit) || !strings.Contains(stderr, "Unpacked local:tiny") {
		t.Fatalf("cmdUnpack explicit stdout=%q stderr=%q", stdout, stderr)
	}
	if b, err := os.ReadFile(filepath.Join(explicit, "hello")); err != nil || string(b) != "world" {
		t.Fatalf("explicit rootfs hello = %q, err=%v; want world", b, err)
	}

	defaultRootfs, err := defaultRootfsForDigest(s.root, digest)
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err = captureOutput(t, func() error {
		return cmdUnpack([]string{"--store", s.root, "local:tiny"})
	})
	if err != nil {
		t.Fatalf("cmdUnpack default: %v", err)
	}
	if stdout != "" || !strings.Contains(stderr, defaultRootfs) {
		t.Fatalf("cmdUnpack default stdout=%q stderr=%q, want default rootfs path", stdout, stderr)
	}
	if b, err := os.ReadFile(filepath.Join(defaultRootfs, "hello")); err != nil || string(b) != "world" {
		t.Fatalf("default rootfs hello = %q, err=%v; want world", b, err)
	}
}

func TestCmdRunPlainRootfsUnpacksInjectsAndExecs(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:a", buildImage(t, []string{"/image-cmd"})); err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(t.TempDir(), "rootfs")
	var gotRootfs string
	var gotSpec *runSpec
	withFakeExecElfuse(t, func(rootfs string, spec *runSpec, lock *flockFile) error {
		gotRootfs = rootfs
		gotSpec = spec
		if b, err := os.ReadFile(filepath.Join(rootfs, "hello")); err != nil || string(b) != "world" {
			t.Fatalf("rootfs hello = %q, err=%v; want world before exec", b, err)
		}
		for _, name := range []string{"hostname", "hosts", "resolv.conf"} {
			if _, err := os.Stat(filepath.Join(rootfs, "etc", name)); err != nil {
				t.Fatalf("runtime file %s missing before exec: %v", name, err)
			}
		}
		return nil
	})

	stderrExpected := "Unpacking local:a -> " + rootfs
	stdout, stderr, err := captureOutput(t, func() error {
		return cmdRun([]string{
			"--store", s.root,
			"--plain-rootfs",
			"--rootfs", rootfs,
			"--env", "A=2",
			"local:a",
			"/cli-cmd", "arg",
		})
	})
	if err != nil {
		t.Fatalf("cmdRun --plain-rootfs: %v", err)
	}
	if stdout != "" || !strings.Contains(stderr, stderrExpected) {
		t.Fatalf("cmdRun stdout=%q stderr=%q, want unpack message %q", stdout, stderr, stderrExpected)
	}
	if gotRootfs != rootfs {
		t.Fatalf("exec rootfs = %q, want %q", gotRootfs, rootfs)
	}
	if gotSpec == nil {
		t.Fatal("exec spec was nil")
	}
	if !reflect.DeepEqual(gotSpec.Args, []string{"/cli-cmd", "arg"}) {
		t.Fatalf("spec args = %v, want CLI tail", gotSpec.Args)
	}
	if !reflect.DeepEqual(gotSpec.Env, []string{"A=2", "PATH=" + defaultGuestPath}) {
		t.Fatalf("spec env = %v, want [A=2] plus default PATH", gotSpec.Env)
	}
}

func TestCmdRunPlainRootfsEntrypointOverride(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:a", buildImage(t, []string{"/image-cmd"})); err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(t.TempDir(), "rootfs")
	var gotSpec *runSpec
	withFakeExecElfuse(t, func(_ string, spec *runSpec, _ *flockFile) error {
		gotSpec = spec
		return nil
	})

	_, _, err := captureOutput(t, func() error {
		return cmdRun([]string{
			"--store", s.root, "--plain-rootfs", "--rootfs", rootfs,
			"--entrypoint", "/override", "local:a", "x", "y",
		})
	})
	if err != nil {
		t.Fatalf("cmdRun --entrypoint: %v", err)
	}
	if gotSpec == nil {
		t.Fatal("exec spec was nil")
	}
	// --entrypoint replaces the image Entrypoint AND drops the image Cmd; the
	// CLI tail becomes the new Cmd.
	if want := []string{"/override", "x", "y"}; !reflect.DeepEqual(gotSpec.Args, want) {
		t.Fatalf("spec args = %v, want %v", gotSpec.Args, want)
	}
}

func TestCmdRunPlainRootfsExistingSkipsUnpack(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:a", buildImage(t, []string{"/image-cmd"})); err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(t.TempDir(), "existing-rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}

	withFakeExecElfuse(t, func(rootfs string, spec *runSpec, lock *flockFile) error {
		if _, err := os.Stat(filepath.Join(rootfs, "hello")); !os.IsNotExist(err) {
			t.Fatalf("existing rootfs was unpacked over: stat hello = %v, want IsNotExist", err)
		}
		if !reflect.DeepEqual(spec.Args, []string{"/image-cmd"}) {
			t.Fatalf("spec args = %v, want image cmd", spec.Args)
		}
		return nil
	})

	_, stderr, err := captureOutput(t, func() error {
		return cmdRun([]string{"--store", s.root, "--plain-rootfs", "--rootfs", rootfs, "local:a"})
	})
	if err != nil {
		t.Fatalf("cmdRun existing rootfs: %v", err)
	}
	if strings.Contains(stderr, "Unpacking") {
		t.Fatalf("existing rootfs stderr = %q, want no unpack message", stderr)
	}
}

func TestCmdRunPlainRootfsAutoPullsMissingImage(t *testing.T) {
	root := t.TempDir()
	rootfs := filepath.Join(t.TempDir(), "rootfs")
	pullCalls := 0
	withFakeCranePull(t, func(ref string, opts ...crane.Option) (v1.Image, error) {
		pullCalls++
		if ref != "local:pulled" {
			t.Fatalf("pull ref = %q, want local:pulled", ref)
		}
		return buildImage(t, []string{"/pulled-cmd"}), nil
	})
	withFakeExecElfuse(t, func(rootfs string, spec *runSpec, lock *flockFile) error {
		if !reflect.DeepEqual(spec.Args, []string{"/pulled-cmd"}) {
			t.Fatalf("spec args = %v, want pulled image cmd", spec.Args)
		}
		return nil
	})

	stdout, stderr, err := captureOutput(t, func() error {
		return cmdRun([]string{"--store", root, "--plain-rootfs", "--rootfs", rootfs, "local:pulled"})
	})
	if err != nil {
		t.Fatalf("cmdRun auto-pull: %v", err)
	}
	if pullCalls != 1 {
		t.Fatalf("pullCalls = %d, want 1", pullCalls)
	}
	// run's stdout belongs to the guest (callers capture it), so the pull
	// summary must land on stderr with the unpack progress.
	if strings.Contains(stdout, "Pulled local:pulled") {
		t.Fatalf("cmdRun auto-pull stdout = %q, pull summary leaked into guest stdout", stdout)
	}
	if !strings.Contains(stderr, "Pulled local:pulled") || !strings.Contains(stderr, "Unpacking local:pulled") {
		t.Fatalf("cmdRun auto-pull stderr = %q, want pull and unpack summaries", stderr)
	}
	s, err := openStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.digestFor("local:pulled"); err != nil {
		t.Fatalf("auto-pulled ref was not pinned: %v", err)
	}
}

func TestCommandWrappersReturnParseAndStoreErrors(t *testing.T) {
	parseCases := []struct {
		name string
		fn   func() error
	}{
		{"pull", func() error { return cmdPull(nil) }},
		{"unpack", func() error { return cmdUnpack(nil) }},
		{"inspect", func() error { return cmdInspect(nil) }},
		{"run", func() error { return cmdRun(nil) }},
		{"list", func() error { return cmdList([]string{"extra"}) }},
		{"rmi", func() error { return cmdRmi(nil) }},
		{"prune", func() error { return cmdPrune([]string{"--all"}) }},
	}
	for _, tc := range parseCases {
		t.Run("parse "+tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Fatalf("%s parse error case succeeded, want error", tc.name)
			}
		})
	}

	storeFile := filepath.Join(t.TempDir(), "store-file")
	if err := os.WriteFile(storeFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	storeCases := []struct {
		name string
		fn   func() error
	}{
		{"pull", func() error { return cmdPull([]string{"--store", storeFile, "local:a"}) }},
		{"unpack", func() error { return cmdUnpack([]string{"--store", storeFile, "local:a"}) }},
		{"inspect", func() error { return cmdInspect([]string{"--store", storeFile, "local:a"}) }},
		{"run", func() error { return cmdRun([]string{"--store", storeFile, "local:a"}) }},
		{"list", func() error { return cmdList([]string{"--store", storeFile}) }},
		{"rmi", func() error { return cmdRmi([]string{"--store", storeFile, "local:a"}) }},
		{"prune", func() error { return cmdPrune([]string{"--store", storeFile}) }},
	}
	for _, tc := range storeCases {
		t.Run("store "+tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Fatalf("%s store error case succeeded, want error", tc.name)
			}
		})
	}
}

// TestCmdRunPlatformMismatchOnPinnedRef pins the --platform check: the store
// pins one digest per ref, so an explicit --platform that disagrees with the
// pinned image must fail instead of silently launching the wrong
// architecture. Without --platform the pinned image runs as-is.
func TestCmdRunPlatformMismatchOnPinnedRef(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:a", buildImage(t, []string{"/image-cmd"})); err != nil {
		t.Fatal(err)
	}
	withFakeExecElfuse(t, func(string, *runSpec, *flockFile) error { return nil })
	rootfs := filepath.Join(t.TempDir(), "rootfs")

	_, _, err := captureOutput(t, func() error {
		return cmdRun([]string{
			"--store", s.root, "--platform", "linux/amd64",
			"--plain-rootfs", "--rootfs", rootfs, "local:a",
		})
	})
	if err == nil || !strings.Contains(err.Error(), "pinned for linux/arm64") {
		t.Fatalf("cmdRun --platform mismatch err = %v, want pinned-platform error", err)
	}

	for _, args := range [][]string{
		{"--store", s.root, "--platform", "linux/arm64", "--plain-rootfs", "--rootfs", rootfs, "local:a"},
		{"--store", s.root, "--plain-rootfs", "--rootfs", rootfs, "local:a"},
	} {
		if _, _, err := captureOutput(t, func() error { return cmdRun(args) }); err != nil {
			t.Fatalf("cmdRun %v: %v", args, err)
		}
	}
}

// TestCmdRunPlainRootfsLockDiscipline pins which runs hold the per-digest
// cache lock at exec time: a store-default rootfs arrives with the run lock
// held (a concurrent prune would see busy), while an explicit --rootfs is
// user-managed and locks nothing.
func TestCmdRunPlainRootfsLockDiscipline(t *testing.T) {
	s := openTestStore(t)
	img := buildImage(t, []string{"/image-cmd"})
	if _, err := s.addImage("local:a", img); err != nil {
		t.Fatal(err)
	}

	var gotLock *flockFile
	var busyAtExec bool
	withFakeExecElfuse(t, func(rootfs string, spec *runSpec, lock *flockFile) error {
		gotLock = lock
		busyAtExec = rootfsCacheBusy(rootfs)
		return nil
	})
	if _, _, err := captureOutput(t, func() error {
		return cmdRun([]string{"--store", s.root, "--plain-rootfs", "local:a"})
	}); err != nil {
		t.Fatalf("cmdRun store-default: %v", err)
	}
	if gotLock == nil {
		t.Error("store-default rootfs exec got nil lock, want held run lock")
	}
	if !busyAtExec {
		t.Error("store-default cache not busy at exec time, want lock held")
	}

	gotLock = nil
	rootfs := filepath.Join(t.TempDir(), "explicit")
	if _, _, err := captureOutput(t, func() error {
		return cmdRun([]string{"--store", s.root, "--plain-rootfs", "--rootfs", rootfs, "local:a"})
	}); err != nil {
		t.Fatalf("cmdRun explicit rootfs: %v", err)
	}
	if gotLock != nil {
		t.Error("explicit --rootfs exec got a lock, want nil")
	}
}

// markedImage builds a single-layer image whose /marker file holds content, so
// a test can tell which image populated a digest-keyed cache.
func markedImage(t *testing.T, content string) v1.Image {
	t.Helper()
	return testImageWithLayers(t, testTarLayer(t,
		tarEntry{header: regHeader("marker", 0o644, 0), body: content}))
}

// TestCmdUnpackUsesResolvedImageDespiteRepull pins that unpack fills the
// digest-keyed cache from the image it resolved, not a re-resolution of the
// mutable ref: a repull that moves the tag to a different image mid-setup must
// not poison digest A's cache with image B's content (#8). The afterImageResolve
// seam fires in the exact window between resolution and unpack.
func TestCmdUnpackUsesResolvedImageDespiteRepull(t *testing.T) {
	s := openTestStore(t)
	imgA := markedImage(t, "image-A")
	imgB := markedImage(t, "image-B")
	digestA, err := s.addImage("local:tag", imgA)
	if err != nil {
		t.Fatal(err)
	}

	old := afterImageResolve
	t.Cleanup(func() { afterImageResolve = old })
	repinned := false
	afterImageResolve = func(digest string) {
		if repinned || digest != digestA {
			return
		}
		repinned = true
		// Move the tag to image B while the unpack still holds digest A's
		// reference lock. addImage takes the store lock, which resolveImageForUse
		// has already released by now.
		if _, err := s.addImage("local:tag", imgB); err != nil {
			t.Errorf("repull to image B: %v", err)
		}
	}

	if _, _, err := captureOutput(t, func() error {
		return cmdUnpack([]string{"--store", s.root, "local:tag"})
	}); err != nil {
		t.Fatalf("cmdUnpack: %v", err)
	}
	if !repinned {
		t.Fatal("afterImageResolve never fired for digest A")
	}
	rootfsA, err := defaultRootfsForDigest(s.root, digestA)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(rootfsA, "marker")); err != nil || string(b) != "image-A" {
		t.Fatalf("digest-A cache marker = %q, err=%v; want image-A (not poisoned by repull)", b, err)
	}
}

// TestRmiRefusesWhileReferenceLockHeld pins #6: a starting run holds the
// per-digest reference lock before any cache dir or bundle exists, so rmi of
// the last pin must refuse (even with --force) rather than GC blobs out from
// under it, and the pin plus its blobs survive the refusal. Once the lock is
// released the same rmi succeeds.
func TestRmiRefusesWhileReferenceLockHeld(t *testing.T) {
	s := openTestStore(t)
	img := tinyImage(t)
	digest, err := s.addImage("local:a", img)
	if err != nil {
		t.Fatal(err)
	}
	rootfs, err := defaultRootfsForDigest(s.root, digest)
	if err != nil {
		t.Fatal(err)
	}
	// A cold run's reference lock: taken before the rootfs cache dir exists.
	hold, err := acquireRootfsRunLock(rootfs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rootfs); !os.IsNotExist(err) {
		t.Fatalf("cache dir exists before run unpacked it: %v", err)
	}

	if _, err := s.rmi("local:a", true); err == nil {
		t.Fatal("rmi --force succeeded while reference lock held, want refusal")
	}
	if _, err := s.image("local:a"); err != nil {
		t.Fatalf("pin/blobs gone after refused rmi: %v", err)
	}

	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.rmi("local:a", false); err != nil {
		t.Fatalf("rmi after lock released: %v", err)
	}
}
