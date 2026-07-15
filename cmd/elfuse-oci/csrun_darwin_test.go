// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"archive/tar"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sys/unix"
)

type runExitCode int

func withCSRunSeams(t *testing.T) {
	t.Helper()
	oldEnsure := ensureCaseSensitiveRootfsForRun
	oldClone := clonefileForRun
	oldSpawn := spawnElfuseWaitForRun
	oldCleanup := cleanupCloneAndMountForRun
	oldSidecar := writeKeptSidecarForRun
	oldExit := osExitForRun
	oldNow := runNowUnixNano
	t.Cleanup(func() {
		ensureCaseSensitiveRootfsForRun = oldEnsure
		clonefileForRun = oldClone
		spawnElfuseWaitForRun = oldSpawn
		cleanupCloneAndMountForRun = oldCleanup
		writeKeptSidecarForRun = oldSidecar
		osExitForRun = oldExit
		runNowUnixNano = oldNow
	})
}

func TestRunCaseSensitiveCloneSpawnCleanupAndExit(t *testing.T) {
	withCSRunSeams(t)
	mount := t.TempDir()
	base := filepath.Join(mount, "rootfs")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	m := &csMount{mountPath: mount}
	runNowUnixNano = func() int64 { return 123 }
	expectedClone := filepath.Join(mount, fmt.Sprintf("run-%d-123", os.Getpid()))
	var clonedSrc, clonedDst string
	ensureCaseSensitiveRootfsForRun = func(cf commonFlags, s *store, ref string, img v1.Image, digest, size string) (*csMount, string, error) {
		if cf.store != "store" || ref != "local:a" || digest != "sha256:"+strings.Repeat("7", 64) || size != "64m" {
			t.Fatalf("ensure args = store=%q ref=%q digest=%q size=%q", cf.store, ref, digest, size)
		}
		return m, base, nil
	}
	clonefileForRun = func(src, dst string, flags int) error {
		clonedSrc, clonedDst = src, dst
		if flags != unix.CLONE_NOFOLLOW {
			t.Fatalf("clone flags = %d, want CLONE_NOFOLLOW", flags)
		}
		return os.MkdirAll(dst, 0o755)
	}
	var spawnRootfs string
	var spawnSpec *runSpec
	spawnElfuseWaitForRun = func(rootfs string, spec *runSpec) (int, error) {
		spawnRootfs = rootfs
		spawnSpec = spec
		return 7, nil
	}
	var cleanupClone string
	var cleanupKeep bool
	cleanupCloneAndMountForRun = func(cloneDir string, keep bool, got *csMount) error {
		cleanupClone, cleanupKeep = cloneDir, keep
		if got != m {
			t.Fatalf("cleanup mount = %+v, want fake mount", got)
		}
		return nil
	}
	osExitForRun = func(code int) { panic(runExitCode(code)) }

	defer func() {
		r := recover()
		code, ok := r.(runExitCode)
		if !ok || code != 7 {
			t.Fatalf("runCaseSensitive panic = %T %v, want exit code 7", r, r)
		}
		if clonedSrc != base || clonedDst != expectedClone {
			t.Fatalf("clone = %q -> %q, want %q -> %q", clonedSrc, clonedDst, base, expectedClone)
		}
		if spawnRootfs != expectedClone {
			t.Fatalf("spawn rootfs = %q, want clone %q", spawnRootfs, expectedClone)
		}
		if spawnSpec == nil || !reflect.DeepEqual(spawnSpec.Args, []string{"/cmd"}) {
			t.Fatalf("spawn spec = %+v, want /cmd", spawnSpec)
		}
		if cleanupClone != expectedClone || cleanupKeep {
			t.Fatalf("cleanup clone=%q keep=%v, want clone and keep=false", cleanupClone, cleanupKeep)
		}
	}()

	cfg := &v1.ConfigFile{Config: v1.Config{Cmd: []string{"/cmd"}}}
	err := runCaseSensitive(
		commonFlags{store: "store"},
		&store{},
		"local:a",
		nil,
		"sha256:"+strings.Repeat("7", 64),
		cfg,
		runFlags{sparseSize: "64m"},
		nil,
	)
	t.Fatalf("runCaseSensitive returned %v, want osExitForRun panic", err)
}

func TestRunCaseSensitiveNoCloneKeepSkipsCleanup(t *testing.T) {
	withCSRunSeams(t)
	mount := t.TempDir()
	base := filepath.Join(mount, "rootfs")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	ensureCaseSensitiveRootfsForRun = func(commonFlags, *store, string, v1.Image, string, string) (*csMount, string, error) {
		return &csMount{mountPath: mount}, base, nil
	}
	clonefileForRun = func(string, string, int) error {
		t.Fatal("clonefile called with --no-clone")
		return nil
	}
	spawnElfuseWaitForRun = func(rootfs string, spec *runSpec) (int, error) {
		if rootfs != base {
			t.Fatalf("spawn rootfs = %q, want base rootfs", rootfs)
		}
		return 0, nil
	}
	cleanupCloneAndMountForRun = func(string, bool, *csMount) error {
		t.Fatal("cleanup called with --keep")
		return nil
	}
	// --no-clone --keep still records the keep beside the bundle so a cold rmi
	// refuses to discard the mutated base tree without --force.
	sidecarWritten := false
	writeKeptSidecarForRun = func(*csMount) error {
		sidecarWritten = true
		return nil
	}
	osExitForRun = func(code int) { panic(runExitCode(code)) }

	defer func() {
		r := recover()
		code, ok := r.(runExitCode)
		if !ok || code != 0 {
			t.Fatalf("runCaseSensitive panic = %T %v, want exit code 0", r, r)
		}
		if !sidecarWritten {
			t.Error("--no-clone --keep did not write the kept sidecar")
		}
	}()
	err := runCaseSensitive(commonFlags{}, &store{}, "local:a", nil, "sha256:"+strings.Repeat("8", 64),
		&v1.ConfigFile{Config: v1.Config{Cmd: []string{"/cmd"}}},
		runFlags{noClone: true, keepRootfs: true},
		nil)
	t.Fatalf("runCaseSensitive returned %v, want exit panic", err)
}

func TestRunCaseSensitiveSpecErrorCleansCloneAndMount(t *testing.T) {
	withCSRunSeams(t)
	mount := t.TempDir()
	base := filepath.Join(mount, "rootfs")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	m := &csMount{mountPath: mount}
	runNowUnixNano = func() int64 { return 456 }
	expectedClone := filepath.Join(mount, fmt.Sprintf("run-%d-456", os.Getpid()))
	ensureCaseSensitiveRootfsForRun = func(commonFlags, *store, string, v1.Image, string, string) (*csMount, string, error) {
		return m, base, nil
	}
	clonefileForRun = func(src, dst string, flags int) error {
		return os.MkdirAll(dst, 0o755)
	}
	spawnElfuseWaitForRun = func(string, *runSpec) (int, error) {
		t.Fatal("spawn called after spec error")
		return 0, nil
	}
	var cleanupClone string
	cleanupCloneAndMountForRun = func(cloneDir string, keep bool, got *csMount) error {
		cleanupClone = cloneDir
		if keep {
			t.Fatal("cleanup keep = true, want false")
		}
		if got != m {
			t.Fatalf("cleanup mount = %+v, want fake mount", got)
		}
		return nil
	}
	osExitForRun = func(code int) { t.Fatalf("exit called after spec error with code %d", code) }

	err := runCaseSensitive(commonFlags{}, &store{}, "local:a", nil, "sha256:"+strings.Repeat("9", 64),
		&v1.ConfigFile{Config: v1.Config{}},
		runFlags{},
		nil)
	if err == nil || !strings.Contains(err.Error(), "no command") {
		t.Fatalf("runCaseSensitive spec err = %v, want no command", err)
	}
	if cleanupClone != expectedClone {
		t.Fatalf("cleanup clone = %q, want %q", cleanupClone, expectedClone)
	}
}

func TestEnsureCaseSensitiveRootfsProvisionsUnpacksAndSkipsExisting(t *testing.T) {
	t.Run("unpacks missing rootfs", func(t *testing.T) {
		installFakeHdiutil(t)
		withDarwinCacheSeams(t, func(string) bool { return false }, nil)
		actualMount := filepath.Join(t.TempDir(), "actual-mount")
		if err := os.MkdirAll(actualMount, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HDIUTIL_MOUNT", actualMount)
		s := openTestStore(t)
		digest, err := s.addImage("local:tiny", tinyImage(t))
		if err != nil {
			t.Fatal(err)
		}
		img, err := s.image("local:tiny")
		if err != nil {
			t.Fatal(err)
		}

		m, rootfs, err := ensureCaseSensitiveRootfs(commonFlags{store: s.root}, s, "local:tiny", img, digest, "32m")
		if err != nil {
			t.Fatalf("ensureCaseSensitiveRootfs: %v", err)
		}
		t.Cleanup(func() { _ = m.Close() })
		if rootfs != filepath.Join(actualMount, "rootfs") {
			t.Fatalf("rootfs = %q, want actual mount rootfs", rootfs)
		}
		if b, err := os.ReadFile(filepath.Join(rootfs, "hello")); err != nil || string(b) != "world" {
			t.Fatalf("rootfs hello = %q, err=%v; want world", b, err)
		}
	})

	t.Run("keeps existing rootfs", func(t *testing.T) {
		installFakeHdiutil(t)
		withDarwinCacheSeams(t, func(string) bool { return false }, nil)
		actualMount := filepath.Join(t.TempDir(), "actual-mount")
		rootfs := filepath.Join(actualMount, "rootfs")
		if err := os.MkdirAll(rootfs, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rootfs, "marker"), []byte("keep"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HDIUTIL_MOUNT", actualMount)
		s := openTestStore(t)
		digest, err := s.addImage("local:tiny", tinyImage(t))
		if err != nil {
			t.Fatal(err)
		}
		img, err := s.image("local:tiny")
		if err != nil {
			t.Fatal(err)
		}

		m, gotRootfs, err := ensureCaseSensitiveRootfs(commonFlags{store: s.root}, s, "local:tiny", img, digest, "32m")
		if err != nil {
			t.Fatalf("ensureCaseSensitiveRootfs existing: %v", err)
		}
		t.Cleanup(func() { _ = m.Close() })
		if gotRootfs != rootfs {
			t.Fatalf("rootfs = %q, want %q", gotRootfs, rootfs)
		}
		if b, err := os.ReadFile(filepath.Join(rootfs, "marker")); err != nil || string(b) != "keep" {
			t.Fatalf("marker = %q, err=%v; want keep", b, err)
		}
		if _, err := os.Stat(filepath.Join(rootfs, "hello")); !os.IsNotExist(err) {
			t.Fatalf("existing rootfs was unpacked over: %v", err)
		}
	})
}

func TestEnsureCaseSensitiveRootfsClosesMountOnUnpackError(t *testing.T) {
	installFakeHdiutil(t)
	withDarwinCacheSeams(t, func(string) bool { return false }, nil)
	actualMount := filepath.Join(t.TempDir(), "actual-mount")
	if err := os.MkdirAll(actualMount, 0o755); err != nil {
		t.Fatal(err)
	}
	detachLog := filepath.Join(t.TempDir(), "detach.log")
	t.Setenv("HDIUTIL_MOUNT", actualMount)
	t.Setenv("HDIUTIL_DETACH_LOG", detachLog)
	s := openTestStore(t)

	// The image is resolved by the caller now, so an unpack failure has to come
	// from the image content, not a missing ref (that is caught upstream in
	// resolveImageForUse). A fifo entry is an unsupported special file, so
	// unpackImage fails and ensureCaseSensitiveRootfs must still detach the
	// mount it attached.
	bad := testImageWithLayers(t, testTarLayer(t,
		tarEntry{header: tar.Header{Name: "dev/fifo", Typeflag: tar.TypeFifo, Mode: 0o644}}))
	digest, err := s.addImage("local:bad", bad)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ensureCaseSensitiveRootfs(commonFlags{store: s.root}, s, "local:bad", bad, digest, "32m")
	if err == nil || !strings.Contains(err.Error(), "fifo") {
		t.Fatalf("ensureCaseSensitiveRootfs err = %v, want unpack fifo error", err)
	}
	b, readErr := os.ReadFile(detachLog)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(b), actualMount) {
		t.Fatalf("detach log = %q, want actual mount %s", b, actualMount)
	}
}

func TestCleanupCloneAndMountAndCloseMount(t *testing.T) {
	oldDetach := detachForce
	var detached string
	detachForce = func(path string) error {
		detached = path
		return nil
	}
	t.Cleanup(func() { detachForce = oldDetach })

	clone := filepath.Join(t.TempDir(), "clone")
	if err := os.MkdirAll(clone, 0o755); err != nil {
		t.Fatal(err)
	}
	m := &csMount{mountPath: "/tmp/cleanup-mount", owned: true}
	if err := cleanupCloneAndMount(clone, false, m); err != nil {
		t.Fatalf("cleanupCloneAndMount: %v", err)
	}
	if _, err := os.Stat(clone); !os.IsNotExist(err) {
		t.Fatalf("clone after cleanup: %v, want IsNotExist", err)
	}
	if detached != "/tmp/cleanup-mount" || m.owned {
		t.Fatalf("detached=%q owned=%v, want detached mount and owned=false", detached, m.owned)
	}

	detachForce = func(path string) error { return fmt.Errorf("detach boom") }
	err := closeMount(&csMount{mountPath: "/tmp/bad-mount", owned: true})
	if err == nil || !strings.Contains(err.Error(), "detach /tmp/bad-mount") || !strings.Contains(err.Error(), "detach boom") {
		t.Fatalf("closeMount err = %v, want wrapped detach error", err)
	}
}

func TestCmdRunDefaultCaseSensitivePath(t *testing.T) {
	withCSRunSeams(t)
	s := openTestStore(t)
	if _, err := s.addImage("local:a", buildImage(t, []string{"/image-cmd"})); err != nil {
		t.Fatal(err)
	}
	mount := t.TempDir()
	base := filepath.Join(mount, "rootfs")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	runNowUnixNano = func() int64 { return 789 }
	ensureCaseSensitiveRootfsForRun = func(cf commonFlags, _ *store, ref string, img v1.Image, digest, size string) (*csMount, string, error) {
		if cf.store != s.root || ref != "local:a" || size != "" {
			t.Fatalf("ensure from cmdRun got store=%q ref=%q size=%q", cf.store, ref, size)
		}
		if !strings.HasPrefix(digest, "sha256:") {
			t.Fatalf("ensure digest = %q, want sha256 digest", digest)
		}
		return &csMount{mountPath: mount}, base, nil
	}
	clonefileForRun = func(src, dst string, flags int) error {
		return os.MkdirAll(dst, 0o755)
	}
	spawnElfuseWaitForRun = func(rootfs string, spec *runSpec) (int, error) {
		if !strings.Contains(rootfs, fmt.Sprintf("run-%d-789", os.Getpid())) {
			t.Fatalf("spawn rootfs = %q, want generated clone", rootfs)
		}
		if !reflect.DeepEqual(spec.Args, []string{"/image-cmd"}) {
			t.Fatalf("spec args = %v, want image cmd", spec.Args)
		}
		return 0, nil
	}
	cleanupCloneAndMountForRun = func(string, bool, *csMount) error { return nil }
	osExitForRun = func(code int) { panic(runExitCode(code)) }

	defer func() {
		r := recover()
		code, ok := r.(runExitCode)
		if !ok || code != 0 {
			t.Fatalf("cmdRun default sparse path panic = %T %v, want exit 0", r, r)
		}
	}()
	err := cmdRun([]string{"--store", s.root, "local:a"})
	t.Fatalf("cmdRun returned %v, want exit panic", err)
}

// TestRunCaseSensitiveNoCloneCreatesNoMarkerDir pins that a --no-clone run
// leaves no run-<pid>-<ns> placeholder in the volume: liveness now rides on
// the bundle's run.lock (held via the csMount), not on a marker directory, so
// none is created and none is cleaned up.
func TestRunCaseSensitiveNoCloneCreatesNoMarkerDir(t *testing.T) {
	withCSRunSeams(t)
	mount := t.TempDir()
	base := filepath.Join(mount, "rootfs")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	m := &csMount{mountPath: mount}
	runNowUnixNano = func() int64 { return 789 }
	cloneName := filepath.Join(mount, fmt.Sprintf("run-%d-789", os.Getpid()))
	ensureCaseSensitiveRootfsForRun = func(commonFlags, *store, string, v1.Image, string, string) (*csMount, string, error) {
		return m, base, nil
	}
	clonefileForRun = func(string, string, int) error {
		t.Fatal("clonefile called with --no-clone")
		return nil
	}
	spawnElfuseWaitForRun = func(rootfs string, spec *runSpec) (int, error) {
		if rootfs != base {
			t.Fatalf("spawn rootfs = %q, want base rootfs", rootfs)
		}
		if _, err := os.Lstat(cloneName); !os.IsNotExist(err) {
			t.Fatalf("--no-clone created a placeholder %q: %v, want none", cloneName, err)
		}
		return 0, nil
	}
	cleanupCloneAndMountForRun = func(clone string, keep bool, cm *csMount) error {
		return removeClone(clone, keep)
	}
	osExitForRun = func(code int) { panic(runExitCode(code)) }

	defer func() {
		r := recover()
		code, ok := r.(runExitCode)
		if !ok || code != 0 {
			t.Fatalf("runCaseSensitive panic = %T %v, want exit code 0", r, r)
		}
	}()
	err := runCaseSensitive(commonFlags{}, &store{}, "local:a", nil, "sha256:"+strings.Repeat("6", 64),
		&v1.ConfigFile{Config: v1.Config{Cmd: []string{"/cmd"}}},
		runFlags{noClone: true},
		nil)
	t.Fatalf("runCaseSensitive returned %v, want exit panic", err)
}

// TestRunCaseSensitiveKeepWritesKeepMarker pins that a --keep run records a
// keep sidecar beside (not inside) its COW clone so a later sweep preserves the
// clone after this run exits and releases run.lock, and so image content or a
// guest cannot forge the keep by writing /.elfuse-keep in the clone.
func TestRunCaseSensitiveKeepWritesKeepMarker(t *testing.T) {
	withCSRunSeams(t)
	mount := t.TempDir()
	base := filepath.Join(mount, "rootfs")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	m := &csMount{mountPath: mount}
	runNowUnixNano = func() int64 { return 321 }
	cloneDir := filepath.Join(mount, fmt.Sprintf("run-%d-321", os.Getpid()))
	ensureCaseSensitiveRootfsForRun = func(commonFlags, *store, string, v1.Image, string, string) (*csMount, string, error) {
		return m, base, nil
	}
	clonefileForRun = func(src, dst string, flags int) error {
		return os.MkdirAll(dst, 0o755)
	}
	spawnElfuseWaitForRun = func(rootfs string, spec *runSpec) (int, error) {
		if rootfs != cloneDir {
			t.Fatalf("spawn rootfs = %q, want clone %q", rootfs, cloneDir)
		}
		if _, err := os.Stat(cloneKeepMarkerPath(mount, filepath.Base(cloneDir))); err != nil {
			t.Fatalf("keep marker during run: %v, want present", err)
		}
		// The keep record must live OUTSIDE the clone (the guest's /), so
		// image content or the guest cannot forge it.
		if _, err := os.Stat(filepath.Join(cloneDir, ".elfuse-keep")); !os.IsNotExist(err) {
			t.Fatalf("keep record found inside the clone: %v, want only the sidecar", err)
		}
		return 0, nil
	}
	cleanupCloneAndMountForRun = func(string, bool, *csMount) error {
		t.Fatal("cleanup called with --keep")
		return nil
	}
	sidecarWritten := false
	writeKeptSidecarForRun = func(*csMount) error {
		sidecarWritten = true
		return nil
	}
	osExitForRun = func(code int) { panic(runExitCode(code)) }

	defer func() {
		r := recover()
		code, ok := r.(runExitCode)
		if !ok || code != 0 {
			t.Fatalf("runCaseSensitive panic = %T %v, want exit code 0", r, r)
		}
		// The kept clone with its marker survives: a later sweep skips it.
		if listed := listSweepableClones(mount); len(listed) != 0 {
			t.Fatalf("listSweepableClones = %v, want the kept clone skipped", listed)
		}
		if !sidecarWritten {
			t.Error("--keep did not write the kept sidecar")
		}
	}()
	err := runCaseSensitive(commonFlags{}, &store{}, "local:a", nil, "sha256:"+strings.Repeat("6", 64),
		&v1.ConfigFile{Config: v1.Config{Cmd: []string{"/cmd"}}},
		runFlags{keepRootfs: true},
		nil)
	t.Fatalf("runCaseSensitive returned %v, want exit panic", err)
}
