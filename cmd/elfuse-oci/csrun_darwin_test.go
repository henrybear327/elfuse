// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
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
	oldExit := osExitForRun
	oldNow := runNowUnixNano
	t.Cleanup(func() {
		ensureCaseSensitiveRootfsForRun = oldEnsure
		clonefileForRun = oldClone
		spawnElfuseWaitForRun = oldSpawn
		cleanupCloneAndMountForRun = oldCleanup
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
	ensureCaseSensitiveRootfsForRun = func(cf commonFlags, s *store, ref, digest, size string) (*csMount, string, error) {
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
	ensureCaseSensitiveRootfsForRun = func(commonFlags, *store, string, string, string) (*csMount, string, error) {
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
	osExitForRun = func(code int) { panic(runExitCode(code)) }

	defer func() {
		r := recover()
		code, ok := r.(runExitCode)
		if !ok || code != 0 {
			t.Fatalf("runCaseSensitive panic = %T %v, want exit code 0", r, r)
		}
	}()
	err := runCaseSensitive(commonFlags{}, &store{}, "local:a", "sha256:"+strings.Repeat("8", 64),
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
	ensureCaseSensitiveRootfsForRun = func(commonFlags, *store, string, string, string) (*csMount, string, error) {
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

	err := runCaseSensitive(commonFlags{}, &store{}, "local:a", "sha256:"+strings.Repeat("9", 64),
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

		m, rootfs, err := ensureCaseSensitiveRootfs(commonFlags{store: s.root}, s, "local:tiny", digest, "32m")
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

		m, gotRootfs, err := ensureCaseSensitiveRootfs(commonFlags{store: s.root}, s, "local:tiny", digest, "32m")
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

	_, _, err := ensureCaseSensitiveRootfs(commonFlags{store: s.root}, s, "local:missing", "sha256:"+strings.Repeat("a", 64), "32m")
	if err == nil || !strings.Contains(err.Error(), "not pulled") {
		t.Fatalf("ensureCaseSensitiveRootfs err = %v, want unpack not-pulled error", err)
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
	ensureCaseSensitiveRootfsForRun = func(cf commonFlags, _ *store, ref, digest, size string) (*csMount, string, error) {
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
