// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// tarEntry is one member of a fixture layer. Type sets the header type
// outright, taking Link as its Linkname and Major as its device major;
// otherwise Link makes a symlink, a trailing "/" a directory, and
// anything else a regular file holding Body.
type tarEntry struct {
	Name  string
	Body  string
	Link  string
	Mode  int64
	Type  byte
	Major int64
}

// buildLayerTar serializes entries into an uncompressed tar stream.
func buildLayerTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.Name, Mode: e.Mode, Size: int64(len(e.Body)), Typeflag: tar.TypeReg}
		if hdr.Mode == 0 {
			hdr.Mode = 0o644
		}
		switch {
		case e.Type != 0:
			hdr.Typeflag = e.Type
			hdr.Size = 0
			hdr.Linkname = e.Link
			hdr.Devmajor = e.Major
		case e.Link != "":
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = e.Link
			hdr.Size = 0
		case e.Name[len(e.Name)-1] == '/':
			hdr.Typeflag = tar.TypeDir
			if e.Mode == 0 {
				hdr.Mode = 0o755
			}
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.Body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return z.Bytes()
}

// testImage describes a fixture image for pushTestImage.
type testImage struct {
	platform ocispec.Platform
	config   ocispec.ImageConfig
	created  *time.Time
	layers   [][]tarEntry
	// rawConfig, when set, is pushed verbatim instead of a marshalled
	// ocispec.Image, for pinning byte-exact --json output.
	rawConfig []byte
}

// pushTestImage writes an in-memory image into the store and returns its
// manifest digest.
func pushTestImage(t *testing.T, s *store, img testImage) string {
	t.Helper()
	if img.platform.OS == "" {
		img.platform = defaultPlatform
	}
	if len(img.layers) == 0 {
		img.layers = [][]tarEntry{{{Name: "hello", Body: "world"}}}
	}

	var layerDescs []ocispec.Descriptor
	var diffIDs []digest.Digest
	for _, entries := range img.layers {
		raw := buildLayerTar(t, entries)
		gz := gzipBytes(t, raw)
		desc := pushBlob(t, s, ocispec.MediaTypeImageLayerGzip, gz)
		layerDescs = append(layerDescs, desc)
		diffIDs = append(diffIDs, digest.FromBytes(raw))
	}

	rawCfg := img.rawConfig
	if rawCfg == nil {
		cfg := ocispec.Image{
			Platform: img.platform,
			Config:   img.config,
			Created:  img.created,
			RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: diffIDs},
		}
		rawCfg = mustJSON(t, cfg)
	}
	cfgDesc := pushBlob(t, s, ocispec.MediaTypeImageConfig, rawCfg)

	man := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    cfgDesc,
		Layers:    layerDescs,
	}
	man.SchemaVersion = 2
	manDesc := pushBlob(t, s, ocispec.MediaTypeImageManifest, mustJSON(t, man))
	return manDesc.Digest.String()
}

// pushBlob writes b into the content store; a blob already present is
// left as is (OpenWriter reports ErrAlreadyExists and WriteBlob returns).
func pushBlob(t *testing.T, s *store, mediaType string, b []byte) ocispec.Descriptor {
	t.Helper()
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(b), Size: int64(len(b))}
	if err := content.WriteBlob(context.Background(), s.content, desc.Digest.String(), bytes.NewReader(b), desc); err != nil {
		t.Fatal(err)
	}
	return desc
}

// storeWithImage creates a temp store holding one pinned fixture image.
func storeWithImage(t *testing.T, ref string, img testImage) (*store, string) {
	t.Helper()
	s := tempStore(t)
	return s, pushAndPin(t, s, ref, img)
}

// pushAndPin is what a pull leaves behind: the blobs and the pin.
func pushAndPin(t *testing.T, s *store, ref string, img testImage) string {
	t.Helper()
	if img.platform.OS == "" {
		img.platform = defaultPlatform
	}
	d := pushTestImage(t, s, img)
	pinImage(t, s, ref, img.platform, d)
	return d
}

// pinImage pins under the store lock, as pullImage does.
func pinImage(t *testing.T, s *store, ref string, p ocispec.Platform, d string) {
	t.Helper()
	err := s.withLock(context.Background(), func() error { return s.pinLocked(ref, platforms.Format(p), d) })
	if err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeShellStub writes an executable /bin/sh script into a fresh temp
// directory and returns its path.
func writeShellStub(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// prependPath puts dir first on PATH for the rest of the test.
func prependPath(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func tempStore(t *testing.T) *store {
	t.Helper()
	s, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// captureOutput swaps os.Stdout and os.Stderr for pipes around fn and
// returns what fn wrote to each.
func captureOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	or, ow, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	er, ew, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = ow, ew
	outCh := make(chan string, 1)
	errCh := make(chan string, 1)
	go func() { var b bytes.Buffer; b.ReadFrom(or); outCh <- b.String() }()
	go func() { var b bytes.Buffer; b.ReadFrom(er); errCh <- b.String() }()
	defer func() {
		os.Stdout, os.Stderr = oldOut, oldErr
	}()
	fn()
	ow.Close()
	ew.Close()
	return <-outCh, <-errCh
}

// mustContain fails unless every want substring appears in got.
func mustContain(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Fatalf("output missing %q:\n%s", w, got)
		}
	}
}

// manifestOf loads the manifest pinned under digest.
func manifestOf(t *testing.T, s *store, digest string) ocispec.Manifest {
	t.Helper()
	m, err := s.manifestFor(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
