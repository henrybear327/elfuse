// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type tarEntry struct {
	header tar.Header
	body   string
}

// unpackRef resolves ref to its pinned image and unpacks it into dest, the
// two-step the production callers do (resolve under the store lock, then
// unpack the resolved image). It fails the test if the ref cannot be
// resolved; the returned error is unpackImage's, so callers testing unpack
// failures still see them.
func unpackRef(t *testing.T, s *store, ref, dest string) error {
	t.Helper()
	img, err := s.image(ref)
	if err != nil {
		t.Fatalf("resolve %s: %v", ref, err)
	}
	return unpackImage(img, dest)
}

func testTarLayer(t *testing.T, entries ...tarEntry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := e.header
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}
	layer, err := tarball.LayerFromOpener(opener)
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

func testImageWithLayers(t *testing.T, layers ...v1.Layer) v1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatal(err)
	}
	diffIDs := make([]v1.Hash, 0, len(layers))
	for _, layer := range layers {
		diffID, err := layer.DiffID()
		if err != nil {
			t.Fatal(err)
		}
		diffIDs = append(diffIDs, diffID)
	}
	img, err = mutate.ConfigFile(img, &v1.ConfigFile{
		Architecture: "arm64",
		OS:           "linux",
		Config:       v1.Config{Cmd: []string{"/bin/sh"}},
		RootFS:       v1.RootFS{Type: "layers", DiffIDs: diffIDs},
	})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func TestUnpackImageAppliesLayersInOrder(t *testing.T) {
	lower := testTarLayer(t,
		tarEntry{header: dirHeader("etc", 0o755)},
		tarEntry{header: regHeader("etc/keep", 0o644, 0), body: "lower"},
		tarEntry{header: regHeader("etc/gone", 0o644, 0), body: "gone"},
		tarEntry{header: dirHeader("opt", 0o755)},
		tarEntry{header: regHeader("opt/lower", 0o644, 0), body: "hidden"},
		tarEntry{header: dirHeader("bin", 0o755)},
		tarEntry{header: regHeader("bin/busybox", 0o755, 0), body: "busy"},
		tarEntry{header: symHeader("bin/sh", "/bin/busybox")},
	)
	upper := testTarLayer(t,
		tarEntry{header: regHeader("etc/keep", 0o600, 0), body: "upper"},
		tarEntry{header: tar.Header{Name: "etc/.wh.gone", Typeflag: tar.TypeReg, Mode: 0o644}},
		tarEntry{header: tar.Header{Name: "opt/.wh..wh..opq", Typeflag: tar.TypeReg, Mode: 0o644}},
		tarEntry{header: regHeader("opt/new", 0o644, 0), body: "new"},
	)

	s := openTestStore(t)
	if _, err := s.addImage("local:layered", testImageWithLayers(t, lower, upper)); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := unpackRef(t, s, "local:layered", dest); err != nil {
		t.Fatalf("unpackImage: %v", err)
	}

	if b, err := os.ReadFile(filepath.Join(dest, "etc", "keep")); err != nil || string(b) != "upper" {
		t.Fatalf("etc/keep = %q, err=%v; want upper", b, err)
	}
	if fi, err := os.Stat(filepath.Join(dest, "etc", "keep")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("etc/keep mode = %v, err=%v; want 0600", fi, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "etc", "gone")); !os.IsNotExist(err) {
		t.Fatalf("whiteout target etc/gone = %v, want IsNotExist", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "opt", "lower")); !os.IsNotExist(err) {
		t.Fatalf("opaque-hidden opt/lower = %v, want IsNotExist", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "opt", "new")); err != nil || string(b) != "new" {
		t.Fatalf("opt/new = %q, err=%v; want new", b, err)
	}
	target, err := os.Readlink(filepath.Join(dest, "bin", "sh"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "busybox" {
		t.Fatalf("bin/sh target = %q, want busybox", target)
	}
}

// TestUnpackImageCleansUpPartialRootfs pins that a failed unpack never leaves
// anything at dest: the run paths infer "unpacked" from the path's existence,
// so a partial tree must not survive (or even be transiently visible under
// dest) to be executed by a later or concurrent run. The temp staging
// directory must not leak either. A pre-existing dest (explicit --rootfs) must
// be preserved.
func TestUnpackImageCleansUpPartialRootfs(t *testing.T) {
	good := testTarLayer(t, tarEntry{header: regHeader("ok", 0o644, 0), body: "x"})
	bad := testTarLayer(t,
		tarEntry{header: tar.Header{Name: "dev/fifo", Typeflag: tar.TypeFifo, Mode: 0o644}})

	s := openTestStore(t)
	if _, err := s.addImage("local:partial", testImageWithLayers(t, good, bad)); err != nil {
		t.Fatal(err)
	}

	parent := t.TempDir()
	dest := filepath.Join(parent, "rootfs")
	if err := unpackRef(t, s, "local:partial", dest); err == nil {
		t.Fatal("unpackImage succeeded, want failure on fifo entry")
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatalf("partial rootfs still present after failed unpack: err=%v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed unpack left litter next to dest: %v", entries)
	}

	pre := t.TempDir()
	sentinel := filepath.Join(pre, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unpackRef(t, s, "local:partial", pre); err == nil {
		t.Fatal("unpackImage succeeded, want failure on fifo entry")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("pre-existing rootfs dir was deleted on failed unpack: %v", err)
	}
}

// TestUnpackImagePreexistingDestUnpacksInPlace pins the explicit --rootfs
// contract: a destination that already exists is merged into in place rather
// than staged-and-renamed, so files the caller already put there survive a
// successful unpack.
func TestUnpackImagePreexistingDestUnpacksInPlace(t *testing.T) {
	layer := testTarLayer(t, tarEntry{header: regHeader("ok", 0o644, 0), body: "x"})
	s := openTestStore(t)
	if _, err := s.addImage("local:merge", testImageWithLayers(t, layer)); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	sentinel := filepath.Join(dest, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unpackRef(t, s, "local:merge", dest); err != nil {
		t.Fatalf("unpackImage: %v", err)
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "keep" {
		t.Fatalf("sentinel = %q, err=%v; want preserved by in-place unpack", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "ok")); err != nil || string(b) != "x" {
		t.Fatalf("ok = %q, err=%v; want unpacked", b, err)
	}
}

func TestApplyLayerErrors(t *testing.T) {
	root, _ := newRoot(t)
	if err := applyLayer(root, fakeLayer{uncompressedErr: errors.New("open failed")}); err == nil ||
		!strings.Contains(err.Error(), "open layer") {
		t.Fatalf("applyLayer open err = %v, want open layer error", err)
	}
	if err := applyLayer(root, fakeLayer{uncompressed: "not a tar archive"}); err == nil ||
		!strings.Contains(err.Error(), "read tar entry") {
		t.Fatalf("applyLayer corrupt tar err = %v, want read tar entry error", err)
	}
}

func TestApplyEntryRootNoOpsHardlinkEscapeAndSymlinkReplacement(t *testing.T) {
	root, dir := newRoot(t)
	for _, name := range []string{".", "/"} {
		h := regHeader(name, 0o644, 0)
		if err := applyEntry(root, &h, strings.NewReader(""), newLayerPaths()); err != nil {
			t.Fatalf("applyEntry root no-op %q: %v", name, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("root no-op entries = %v, want empty root", entries)
	}

	hardlink := linkHeader("escape-link", "../outside")
	if err := applyEntry(root, &hardlink, strings.NewReader(""), newLayerPaths()); err == nil {
		t.Fatal("applyEntry accepted hardlink target escaping root")
	}

	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "replace-me")); err != nil {
		t.Fatal(err)
	}
	file := regHeader("replace-me", 0o644, int64(len("inside")))
	if err := applyEntry(root, &file, strings.NewReader("inside"), newLayerPaths()); err != nil {
		t.Fatalf("applyEntry replacing symlink: %v", err)
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "outside" {
		t.Fatalf("outside target = %q, err=%v; want unchanged", b, err)
	}
	if li, err := os.Lstat(filepath.Join(dir, "replace-me")); err != nil || li.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("replace-me mode = %v, err=%v; want regular file", li, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "replace-me")); err != nil || string(b) != "inside" {
		t.Fatalf("replace-me content = %q, err=%v; want inside", b, err)
	}
}

func TestApplyEntryAdditionalErrorBranches(t *testing.T) {
	t.Run("unsupported tar type", func(t *testing.T) {
		root, _ := newRoot(t)
		h := tar.Header{Name: "weird", Typeflag: 'x'}
		err := applyEntry(root, &h, strings.NewReader(""), newLayerPaths())
		if err == nil || !strings.Contains(err.Error(), "unsupported tar type") || !strings.Contains(err.Error(), tarTypeName('x')) {
			t.Fatalf("unsupported type err = %v, want tar type error", err)
		}
	})

	t.Run("absolute symlink to root", func(t *testing.T) {
		root, dir := newRoot(t)
		h := symHeader("usr/root-link", "/")
		if err := applyEntry(root, &h, strings.NewReader(""), newLayerPaths()); err != nil {
			t.Fatalf("applyEntry symlink to root: %v", err)
		}
		target, err := os.Readlink(filepath.Join(dir, "usr", "root-link"))
		if err != nil {
			t.Fatal(err)
		}
		if target != ".." {
			t.Fatalf("root symlink target = %q, want ..", target)
		}
	})

	t.Run("parent path is regular file", func(t *testing.T) {
		root, dir := newRoot(t)
		parent := regHeader("parent", 0o644, 0)
		if err := applyEntry(root, &parent, strings.NewReader(""), newLayerPaths()); err != nil {
			t.Fatal(err)
		}
		// A non-directory on the parent path is replaced with a real
		// directory (containerd/Docker behavior), not an error: layers may
		// legitimately turn a lower layer's file into a directory.
		child := regHeader("parent/child", 0o644, 0)
		if err := applyEntry(root, &child, strings.NewReader(""), newLayerPaths()); err != nil {
			t.Fatalf("applyEntry child under regular-file parent: %v, want file replaced by directory", err)
		}
		fi, err := os.Lstat(filepath.Join(dir, "parent"))
		if err != nil || !fi.IsDir() {
			t.Fatalf("parent = %v, err=%v; want a real directory", fi, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "parent", "child")); err != nil {
			t.Fatalf("parent/child: %v, want created", err)
		}
	})

	t.Run("opaque missing directory is no-op", func(t *testing.T) {
		root, _ := newRoot(t)
		h := tar.Header{Name: "missing/.wh..wh..opq", Typeflag: tar.TypeReg}
		if err := applyEntry(root, &h, strings.NewReader(""), newLayerPaths()); err != nil {
			t.Fatalf("opaque missing dir: %v", err)
		}
	})

	t.Run("opaque marker under lower-layer regular file replaces it", func(t *testing.T) {
		root, dir := newRoot(t)
		file := regHeader("notdir", 0o644, 0)
		if err := applyEntry(root, &file, strings.NewReader(""), newLayerPaths()); err != nil {
			t.Fatal(err)
		}
		// The opaque marker hides all lower content under the name, so a
		// lower layer's non-directory there is replaced with an empty real
		// directory rather than cleared through or rejected.
		h := tar.Header{Name: "notdir/.wh..wh..opq", Typeflag: tar.TypeReg}
		if err := applyEntry(root, &h, strings.NewReader(""), newLayerPaths()); err != nil {
			t.Fatalf("opaque marker under regular file: %v, want file replaced by empty directory", err)
		}
		fi, err := os.Lstat(filepath.Join(dir, "notdir"))
		if err != nil || !fi.IsDir() {
			t.Fatalf("notdir = %v, err=%v; want a real directory", fi, err)
		}
	})

	t.Run("opaque marker under same-layer regular file is a no-op", func(t *testing.T) {
		root, dir := newRoot(t)
		file := regHeader("notdir", 0o644, 0)
		lp := newLayerPaths()
		if err := applyEntry(root, &file, strings.NewReader(""), lp); err != nil {
			t.Fatal(err)
		}
		h := tar.Header{Name: "notdir/.wh..wh..opq", Typeflag: tar.TypeReg}
		if err := applyEntry(root, &h, strings.NewReader(""), lp); err != nil {
			t.Fatalf("opaque marker under same-layer file: %v, want no-op", err)
		}
		fi, err := os.Lstat(filepath.Join(dir, "notdir"))
		if err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("notdir = %v, err=%v; want the same-layer file kept", fi, err)
		}
	})
}

type fakeLayer struct {
	uncompressed    string
	uncompressedErr error
}

func (f fakeLayer) Digest() (v1.Hash, error) {
	return v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("1", 64)}, nil
}

func (f fakeLayer) DiffID() (v1.Hash, error) {
	return v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("2", 64)}, nil
}

func (f fakeLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func (f fakeLayer) Uncompressed() (io.ReadCloser, error) {
	if f.uncompressedErr != nil {
		return nil, f.uncompressedErr
	}
	return io.NopCloser(strings.NewReader(f.uncompressed)), nil
}

func (f fakeLayer) Size() (int64, error) {
	return int64(len(f.uncompressed)), nil
}

func (f fakeLayer) MediaType() (types.MediaType, error) {
	return types.DockerLayer, nil
}

// TestUnpackOpaqueAfterSameLayerChildren pins the whiteout scoping rule:
// opaque markers hide lower-layer content only. Tar entry order within a
// layer is not guaranteed, so a marker ordered after its directory's own
// same-layer additions must clear the lower content yet keep the additions.
func TestUnpackOpaqueAfterSameLayerChildren(t *testing.T) {
	lower := testTarLayer(t,
		tarEntry{header: dirHeader("opt", 0o755)},
		tarEntry{header: regHeader("opt/lower", 0o644, 0), body: "hidden"},
	)
	upper := testTarLayer(t,
		tarEntry{header: regHeader("opt/new", 0o644, 0), body: "new"},
		tarEntry{header: tar.Header{Name: "opt/.wh..wh..opq", Typeflag: tar.TypeReg, Mode: 0o644}},
	)

	s := openTestStore(t)
	if _, err := s.addImage("local:opq-late", testImageWithLayers(t, lower, upper)); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := unpackRef(t, s, "local:opq-late", dest); err != nil {
		t.Fatalf("unpackImage: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dest, "opt", "lower")); !os.IsNotExist(err) {
		t.Fatalf("opaque-hidden opt/lower = %v, want IsNotExist", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "opt", "new")); err != nil || string(b) != "new" {
		t.Fatalf("opt/new = %q, err=%v; want same-layer addition to survive the late marker", b, err)
	}
}

// TestUnpackOpaqueAfterImplicitParentChildren pins #1: a late opaque marker
// must preserve the current layer's descendants even when their immediate
// parent directory has no tar entry of its own (an implicit parent, created
// only because a deeper file needed it). Here the upper layer writes
// dir/sub/file with NO dir/sub entry, then an opaque marker on dir: dir/sub and
// its file must survive while the lower layer's dir/old is cleared.
func TestUnpackOpaqueAfterImplicitParentChildren(t *testing.T) {
	lower := testTarLayer(t,
		tarEntry{header: dirHeader("dir", 0o755)},
		tarEntry{header: regHeader("dir/old", 0o644, 0), body: "hidden"},
	)
	upper := testTarLayer(t,
		// No dir/sub entry: the parent is implicit, created for dir/sub/file.
		tarEntry{header: regHeader("dir/sub/file", 0o644, 0), body: "kept"},
		tarEntry{header: tar.Header{Name: "dir/.wh..wh..opq", Typeflag: tar.TypeReg, Mode: 0o644}},
	)

	s := openTestStore(t)
	if _, err := s.addImage("local:opq-implicit", testImageWithLayers(t, lower, upper)); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := unpackRef(t, s, "local:opq-implicit", dest); err != nil {
		t.Fatalf("unpackImage: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dest, "dir", "old")); !os.IsNotExist(err) {
		t.Fatalf("opaque-hidden dir/old = %v, want IsNotExist", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "dir", "sub", "file")); err != nil || string(b) != "kept" {
		t.Fatalf("dir/sub/file = %q, err=%v; want the implicit-parent child to survive the late marker", b, err)
	}
}

// TestUnpackRejectsBareWhiteout pins that a malformed ".wh." entry with no
// target suffix fails extraction instead of resolving to Join(dir, "") and
// deleting the containing directory.
func TestUnpackRejectsBareWhiteout(t *testing.T) {
	dest := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dest, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "opt", "keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	hdr := tar.Header{Name: "opt/.wh.", Typeflag: tar.TypeReg, Mode: 0o644}
	if err := applyEntry(root, &hdr, strings.NewReader(""), newLayerPaths()); err == nil {
		t.Fatal("bare .wh. entry applied, want invalid-whiteout error")
	}
	if _, err := os.Stat(filepath.Join(dest, "opt", "keep")); err != nil {
		t.Fatalf("opt/keep after rejected whiteout: %v, want untouched", err)
	}
}

// TestUnpackDirReplacesLowerSymlink pins that a directory entry replaces a
// lower layer's symlink at the same path. Without the replacement, MkdirAll
// resolves through the link and the layer's children land in the link target,
// materializing a different filesystem tree.
func TestUnpackDirReplacesLowerSymlink(t *testing.T) {
	lower := testTarLayer(t,
		tarEntry{header: dirHeader("real", 0o755)},
		tarEntry{header: symHeader("dir", "/real")},
	)
	upper := testTarLayer(t,
		tarEntry{header: dirHeader("dir", 0o755)},
		tarEntry{header: regHeader("dir/f", 0o644, 0), body: "payload"},
	)

	s := openTestStore(t)
	if _, err := s.addImage("local:dir-over-link", testImageWithLayers(t, lower, upper)); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := unpackRef(t, s, "local:dir-over-link", dest); err != nil {
		t.Fatalf("unpackImage: %v", err)
	}

	fi, err := os.Lstat(filepath.Join(dest, "dir"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("dir mode = %v, want a real directory replacing the lower symlink", fi.Mode())
	}
	if b, err := os.ReadFile(filepath.Join(dest, "dir", "f")); err != nil || string(b) != "payload" {
		t.Fatalf("dir/f = %q, err=%v; want payload", b, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "real", "f")); !os.IsNotExist(err) {
		t.Fatalf("real/f = %v, want IsNotExist (children must not leak through the lower symlink)", err)
	}
}

// TestUnpackParentSymlinkReplaced pins that an entry whose parent path
// component is a lower layer's symlink lands under a real directory at that
// name, not inside the link's target: MkdirAll-style parent creation would
// resolve through the link and write real/sub/f while leaving link/sub/f
// unresolved.
func TestUnpackParentSymlinkReplaced(t *testing.T) {
	lower := testTarLayer(t,
		tarEntry{header: dirHeader("real", 0o755)},
		tarEntry{header: symHeader("link", "/real")},
	)
	upper := testTarLayer(t,
		tarEntry{header: regHeader("link/sub/f", 0o644, 0), body: "payload"},
	)

	s := openTestStore(t)
	if _, err := s.addImage("local:parent-link", testImageWithLayers(t, lower, upper)); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := unpackRef(t, s, "local:parent-link", dest); err != nil {
		t.Fatalf("unpackImage: %v", err)
	}

	fi, err := os.Lstat(filepath.Join(dest, "link"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("link mode = %v, want a real directory replacing the lower symlink", fi.Mode())
	}
	if b, err := os.ReadFile(filepath.Join(dest, "link", "sub", "f")); err != nil || string(b) != "payload" {
		t.Fatalf("link/sub/f = %q, err=%v; want payload", b, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "real", "sub")); !os.IsNotExist(err) {
		t.Fatalf("real/sub = %v, want IsNotExist (entry must not land through the lower symlink)", err)
	}
}

// TestUnpackDirEntryParentSymlinkReplaced is the directory-entry variant of
// TestUnpackParentSymlinkReplaced: a dir entry beneath a lower-layer symlink
// parent must materialize under a real directory, not inside the link target.
func TestUnpackDirEntryParentSymlinkReplaced(t *testing.T) {
	lower := testTarLayer(t,
		tarEntry{header: dirHeader("real", 0o755)},
		tarEntry{header: symHeader("link", "/real")},
	)
	upper := testTarLayer(t,
		tarEntry{header: dirHeader("link/sub", 0o750)},
	)

	s := openTestStore(t)
	if _, err := s.addImage("local:parent-link-dir", testImageWithLayers(t, lower, upper)); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := unpackRef(t, s, "local:parent-link-dir", dest); err != nil {
		t.Fatalf("unpackImage: %v", err)
	}

	fi, err := os.Lstat(filepath.Join(dest, "link"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("link mode = %v, want a real directory replacing the lower symlink", fi.Mode())
	}
	sub, err := os.Lstat(filepath.Join(dest, "link", "sub"))
	if err != nil || !sub.IsDir() || sub.Mode().Perm() != 0o750 {
		t.Fatalf("link/sub = %v, err=%v; want a 0750 directory", sub, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "real", "sub")); !os.IsNotExist(err) {
		t.Fatalf("real/sub = %v, want IsNotExist (dir must not land through the lower symlink)", err)
	}
}

// TestUnpackOpaqueThroughSymlinkKeepsTarget pins that an opaque whiteout whose
// directory is a lower layer's symlink does not clear the link target's
// contents: the marker hides lower content under its own name, so the link is
// replaced with an empty real directory and the target's files survive.
func TestUnpackOpaqueThroughSymlinkKeepsTarget(t *testing.T) {
	lower := testTarLayer(t,
		tarEntry{header: dirHeader("target", 0o755)},
		tarEntry{header: regHeader("target/keep", 0o644, 0), body: "keep"},
		tarEntry{header: symHeader("d", "/target")},
	)
	upper := testTarLayer(t,
		tarEntry{header: tar.Header{Name: "d/.wh..wh..opq", Typeflag: tar.TypeReg, Mode: 0o644}},
	)

	s := openTestStore(t)
	if _, err := s.addImage("local:opaque-link", testImageWithLayers(t, lower, upper)); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := unpackRef(t, s, "local:opaque-link", dest); err != nil {
		t.Fatalf("unpackImage: %v", err)
	}

	if b, err := os.ReadFile(filepath.Join(dest, "target", "keep")); err != nil || string(b) != "keep" {
		t.Fatalf("target/keep = %q, err=%v; want untouched by opaque-through-symlink", b, err)
	}
	fi, err := os.Lstat(filepath.Join(dest, "d"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("d mode = %v, want a real empty directory replacing the symlink", fi.Mode())
	}
	entries, err := os.ReadDir(filepath.Join(dest, "d"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("d entries = %v, want empty", entries)
	}
}
