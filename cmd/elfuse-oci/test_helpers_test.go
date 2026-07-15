// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestMain(m *testing.M) {
	if raw, ok := os.LookupEnv("ELFUSE_OCI_MAIN_TEST_ARGS"); ok {
		var args []string
		if raw != "" {
			args = strings.Split(raw, "\x00")
		}
		os.Args = append([]string{os.Args[0]}, args...)
		main()
		return
	}
	if os.Getenv("ELFUSE_EXEC_ELFUSE_TEST") == "1" {
		spec := &runSpec{
			Args:    []string{"/bin/echo", "hi"},
			Env:     []string{"A=1"},
			Workdir: "/",
			UID:     1,
			GID:     2,
		}
		if err := execElfuse(os.Getenv("ELFUSE_EXEC_ROOTFS"), spec); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(98)
		}
		os.Exit(99)
	}
	os.Exit(m.Run())
}

func sliceContains(xs []string, want string) bool {
	return slices.Contains(xs, want)
}

func captureOutput(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()

	oldStdout, oldStderr := os.Stdout, os.Stderr
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	stdoutCh := make(chan string, 1)
	stderrCh := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(stdoutR)
		stdoutCh <- string(b)
	}()
	go func() {
		b, _ := io.ReadAll(stderrR)
		stderrCh <- string(b)
	}()

	os.Stdout, os.Stderr = stdoutW, stderrW
	defer func() {
		os.Stdout, os.Stderr = oldStdout, oldStderr
	}()

	fnErr := fn()
	_ = stdoutW.Close()
	_ = stderrW.Close()
	stdout := <-stdoutCh
	stderr := <-stderrCh
	_ = stdoutR.Close()
	_ = stderrR.Close()
	return stdout, stderr, fnErr
}

func openTestStore(t *testing.T) *store {
	t.Helper()
	s, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// buildImage builds a one-layer in-memory image whose layer content is fixed
// ("hello"="world") but whose Cmd is cmd, so two calls with different cmds
// produce the same layer blob but distinct config/manifest digests. This is
// what TestRmiKeepsSharedBlobs needs to exercise reachability GC: two pinned
// refs sharing one layer, with distinct manifests.
func buildImage(t *testing.T, cmd []string) v1.Image {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "hello", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	// LayerFromOpener calls the opener per read so digest/diffid can be queried
	// repeatedly (LayerFromReader is deprecated and single-shot).
	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}
	layer, err := tarball.LayerFromOpener(opener)
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	diffID, err := layer.DiffID()
	if err != nil {
		t.Fatal(err)
	}
	img, err = mutate.ConfigFile(img, &v1.ConfigFile{
		Architecture: "arm64",
		OS:           "linux",
		Config:       v1.Config{Cmd: cmd},
		RootFS:       v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diffID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// tinyImage is the canonical single-layer offline test image.
func tinyImage(t *testing.T) v1.Image {
	t.Helper()
	return buildImage(t, []string{"/hello"})
}

func blobPath(root, digest string) string {
	return filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
}

func runMainSubprocess(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "ELFUSE_OCI_MAIN_TEST_ARGS="+strings.Join(args, "\x00"))
	// Buffers instead of pipes: exec.Cmd drains both concurrently, so a child
	// filling one stream can't deadlock against a sequential reader of the
	// other (the pattern the os/exec docs warn about).
	var outB, errB bytes.Buffer
	cmd.Stdout = &outB
	cmd.Stderr = &errB
	waitErr := cmd.Run()
	return outB.String(), errB.String(), waitErr
}
