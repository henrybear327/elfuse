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

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// execSeam records what the exec seam was asked to launch.
type execSeam struct {
	bin    string
	rootfs string
	spec   *runSpec
}

// swapExecSeam records the exec call instead of replacing the process.
func swapExecSeam(t *testing.T) *execSeam {
	t.Helper()
	got := &execSeam{}
	old := execElfuseForRun
	execElfuseForRun = func(bin, rootfs string, spec *runSpec) error {
		got.bin, got.rootfs, got.spec = bin, rootfs, spec
		return nil
	}
	t.Cleanup(func() { execElfuseForRun = old })
	return got
}

func TestCmdRunColdCachePipeline(t *testing.T) {
	stub := writeElfuseStub(t, "exit 0")
	s, d := storeWithImage(t, "app:1", testImage{
		config: ocispec.ImageConfig{
			Entrypoint: []string{"/bin/app"},
			Env:        []string{"FROMIMG=1"},
			WorkingDir: "/srv",
		},
		layers: [][]tarEntry{{{Name: "bin/"}, {Name: "bin/app", Body: "elf", Mode: 0o755}}},
	})
	got := swapExecSeam(t)
	var err error
	_, stderr := captureOutput(t, func() {
		err = cmdRun([]string{"--store", s.root, "app:1", "extra-arg"})
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, stderr, "Unpacking app:1")
	wantRootfs, _ := s.cacheDir(cacheRootfs, d)
	if got.bin != stub || got.rootfs != wantRootfs {
		t.Fatalf("exec %q on %q, want %q on %q", got.bin, got.rootfs, stub, wantRootfs)
	}
	// The tail rides behind the image entrypoint; env and workdir came
	// from the image; /etc was injected into the fresh cache.
	if strings.Join(got.spec.Args, " ") != "/bin/app extra-arg" {
		t.Fatalf("args = %v", got.spec.Args)
	}
	if got.spec.Workdir != "/srv" || envValue(got.spec.Env, "FROMIMG") != "1" {
		t.Fatalf("spec = %+v", got.spec)
	}
	for _, f := range []string{"etc/hostname", "etc/hosts", "etc/resolv.conf", "srv"} {
		if _, err := os.Stat(filepath.Join(wantRootfs, f)); err != nil {
			t.Errorf("prepared rootfs missing %s: %v", f, err)
		}
	}
}

func TestCmdRunWarmCacheNotReunpacked(t *testing.T) {
	writeElfuseStub(t, "exit 0")
	s, d := storeWithImage(t, "app:1", testImage{
		config: ocispec.ImageConfig{Entrypoint: []string{"/bin/sh"}},
		layers: [][]tarEntry{{{Name: "bin/"}, {Name: "bin/sh", Body: "x", Mode: 0o755}}},
	})
	rootfs, _ := s.cacheDir(cacheRootfs, d)
	swapExecSeam(t)
	var err error
	captureOutput(t, func() { err = cmdRun([]string{"--store", s.root, "app:1"}) })
	if err != nil {
		t.Fatal(err)
	}
	// Plant a marker; a second run must reuse the tree untouched.
	marker := filepath.Join(rootfs, "warm-marker")
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr string
	_, stderr = captureOutput(t, func() { err = cmdRun([]string{"--store", s.root, "app:1"}) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr, "Unpacking") {
		t.Fatalf("warm run re-unpacked:\n%s", stderr)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("warm cache was replaced")
	}
}

func TestCmdRunAutoPullOnlyOnNotPulled(t *testing.T) {
	writeElfuseStub(t, "exit 0")
	s, _ := storeWithImage(t, "app:1", testImage{
		config: ocispec.ImageConfig{Entrypoint: []string{"/e"}},
	})
	calls := 0
	old := pullForRun
	pullForRun = func(ctx context.Context, cf commonFlags, st *store, ref string) (string, error) {
		calls++
		// Model the pull landing the pin.
		return pushAndPin(t, st, ref, testImage{platform: cf.platform,
			config: ocispec.ImageConfig{Entrypoint: []string{"/e"}},
			layers: [][]tarEntry{{{Name: "e", Body: "x", Mode: 0o755}}}}), nil
	}
	t.Cleanup(func() { pullForRun = old })
	swapExecSeam(t)

	var err error
	captureOutput(t, func() { err = cmdRun([]string{"--store", s.root, "fresh:1"}) })
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("auto-pull calls = %d, want 1", calls)
	}

	// A corrupt pin table must surface, never trigger a pull.
	if err := os.WriteFile(s.pinsPath(), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	calls = 0
	captureOutput(t, func() { err = cmdRun([]string{"--store", s.root, "other:1"}) })
	if err == nil || calls != 0 {
		t.Fatalf("corrupt store: err = %v, pulls = %d (want error, 0)", err, calls)
	}
}

func TestCmdRunRefusesRootfsInsideStore(t *testing.T) {
	writeElfuseStub(t, "exit 0")
	s := tempStore(t)
	inside := filepath.Join(s.root, "rootfs", "sha256", "aa")
	pulled := false
	old := pullForRun
	pullForRun = func(context.Context, commonFlags, *store, string) (string, error) {
		pulled = true
		return "", errors.New("no network in tests")
	}
	t.Cleanup(func() { pullForRun = old })
	var err error
	captureOutput(t, func() {
		err = cmdRun([]string{"--store", s.root, "--rootfs", inside, "never-pulled:1"})
	})
	if err == nil || !strings.Contains(err.Error(), "inside the store") {
		t.Fatalf("err = %v", err)
	}
	if pulled {
		t.Fatal("the refusal must beat auto-pull: an impossible run must not cost a download")
	}
}
