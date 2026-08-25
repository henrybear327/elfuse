// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/containerd/containerd/v2/pkg/archive"
)

// filterEntries runs entries through a fresh filter and returns the
// accepted headers by name.
func filterEntries(t *testing.T, entries []tarEntry) map[string]*tar.Header {
	t.Helper()
	return filterEntriesWith(t, layerFilter(""), entries)
}

// filterEntriesWith runs one layer's entries through f, so a test can
// feed several layers to the same filter.
func filterEntriesWith(t *testing.T, f archive.Filter, entries []tarEntry) map[string]*tar.Header {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(buildLayerTar(t, entries)))
	got := map[string]*tar.Header{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		ok, err := f(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			got[hdr.Name] = hdr
		}
	}
	return got
}

func TestFilterDropsSpecialFiles(t *testing.T) {
	var got map[string]*tar.Header
	_, stderr := captureOutput(t, func() {
		got = filterEntries(t, []tarEntry{
			{Name: "keep", Body: "x"},
			{Name: "dev-null", Type: tar.TypeChar, Major: 1},
			{Name: "disk", Type: tar.TypeBlock, Major: 8},
			{Name: "pipe", Type: tar.TypeFifo},
		})
	})
	// Each special entry leaves as a whiteout of its own path.
	for name, want := range map[string]bool{
		"keep": true, "dev-null": false, "disk": false, "pipe": false,
		".wh.dev-null": true, ".wh.disk": true, ".wh.pipe": true,
	} {
		if (got[name] != nil) != want {
			t.Errorf("%s: present=%v, want %v", name, got[name] != nil, want)
		}
	}
	for _, wh := range []string{".wh.dev-null", ".wh.disk", ".wh.pipe"} {
		if h := got[wh]; h != nil && (h.Typeflag != tar.TypeReg || h.Size != 0) {
			t.Errorf("%s: type %c size %d, want an empty regular file", wh, h.Typeflag, h.Size)
		}
	}
	mustContain(t, stderr, "dropping special files", "dev-null")
}

func TestFilterClearsSpecialBitsOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only behavior")
	}
	var got map[string]*tar.Header
	_, stderr := captureOutput(t, func() {
		got = filterEntries(t, []tarEntry{
			{Name: "wall", Body: "x", Mode: 0o2755},
			{Name: "sudoish", Body: "x", Mode: 0o4755},
			{Name: "tmpdir/", Mode: 0o1777},
		})
	})
	for name, want := range map[string]int64{"wall": 0o755, "sudoish": 0o755, "tmpdir/": 0o777} {
		if got[name] == nil || got[name].Mode != want {
			t.Errorf("%s: mode = %o, want %o", name, got[name].Mode, want)
		}
	}
	mustContain(t, stderr, "clearing setuid/setgid/sticky")
}

func TestFilterRewritesAbsoluteSymlinks(t *testing.T) {
	long := "usr/share/ca-certificates/mozilla/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.crt"
	got := filterEntries(t, []tarEntry{
		{Name: "usr/bin/sh", Link: "/bin/busybox"},
		{Name: "bin", Link: "/usr/bin"},
		{Name: "loop", Link: "/"},
		{Name: "etc/rel", Link: "../keep"},
		{Name: "etc/ssl/certs/cert.pem", Link: "/" + long},
	})
	for name, want := range map[string]string{
		"usr/bin/sh":             "../../bin/busybox",
		"bin":                    "usr/bin",
		"loop":                   ".",
		"etc/rel":                "../keep",
		"etc/ssl/certs/cert.pem": "../../../" + long,
	} {
		if got[name] == nil || got[name].Linkname != want {
			t.Errorf("%s: linkname = %q, want %q", name, got[name].Linkname, want)
		}
	}
}

// A hardlink whose target was dropped drops too, whichever of the two
// carries a leading slash; one to a kept entry stays.
func TestFilterDropsHardlinkToDroppedNode(t *testing.T) {
	var got map[string]*tar.Header
	captureOutput(t, func() {
		got = filterEntries(t, []tarEntry{
			{Name: "dev/null", Type: tar.TypeChar, Major: 1},
			{Name: "dev/alias", Link: "dev/null", Type: tar.TypeLink},
			{Name: "/dev/zero", Type: tar.TypeChar, Major: 1},
			{Name: "dev/zero-alias", Link: "dev/zero", Type: tar.TypeLink},
			{Name: "dev/zero-abs", Link: "/dev/zero", Type: tar.TypeLink},
			{Name: "keep", Body: "x"},
			{Name: "keep-alias", Link: "keep", Type: tar.TypeLink},
		})
	})
	for name, want := range map[string]bool{
		"dev/null": false, "dev/alias": false,
		"/dev/zero": false, "dev/zero-alias": false, "dev/zero-abs": false,
		"keep": true, "keep-alias": true,
	} {
		if (got[name] != nil) != want {
			t.Errorf("%s: present=%v, want %v", name, got[name] != nil, want)
		}
	}
}

// One filter spans the image: a later layer's hardlink to a node dropped
// earlier drops, until a layer recreates the path.
func TestFilterCarriesDropsAcrossLayers(t *testing.T) {
	f := layerFilter("")
	var link, recreated map[string]*tar.Header
	captureOutput(t, func() {
		filterEntriesWith(t, f, []tarEntry{{Name: "dev/null", Type: tar.TypeChar, Major: 1}})
		link = filterEntriesWith(t, f, []tarEntry{{Name: "dev/alias", Link: "dev/null", Type: tar.TypeLink}})
		recreated = filterEntriesWith(t, f, []tarEntry{
			{Name: "dev/null", Body: "x"},
			{Name: "dev/alias2", Link: "dev/null", Type: tar.TypeLink},
		})
	})
	if link["dev/alias"] != nil {
		t.Error("hardlink to a node dropped in an earlier layer must drop")
	}
	if recreated["dev/null"] == nil || recreated["dev/alias2"] == nil {
		t.Errorf("recreated path and its hardlink must survive, got %v", recreated)
	}
}

// An absolute entry name is taken root-relative like the target, or Rel
// fails on a mixed pair and the link is rewritten to its own directory.
func TestRelativeSymlinkTargetHandlesAbsoluteNames(t *testing.T) {
	for _, c := range []struct{ name, target, want string }{
		{"usr/bin/sh", "/bin/busybox", "../../bin/busybox"},
		{"/usr/bin/sh", "/bin/busybox", "../../bin/busybox"},
		{"/sh", "/bin/busybox", "bin/busybox"},
		{"sh", "/bin/busybox", "bin/busybox"},
	} {
		if got := relativeSymlinkTarget("", c.name, c.target); got != c.want {
			t.Errorf("relativeSymlinkTarget(%q, %q) = %q, want %q", c.name, c.target, got, c.want)
		}
	}
}

// Under a symlinked parent the link lands where the parent points, so
// the relative target is computed from there; an absent parent falls
// back to the tar-name parent.
func TestRelativeSymlinkTargetResolvesSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr", "lib"), 0o755)
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, target, want string }{
		{"lib/bar", "/usr/lib/foo", "foo"},
		{"lib/sub/bar", "/usr/lib/foo", "../foo"},
		{"etc/alt", "/usr/lib/foo", "../usr/lib/foo"},
		{"nonexistent/x", "/bin/sh", "../bin/sh"},
	} {
		if got := relativeSymlinkTarget(root, c.name, c.target); got != c.want {
			t.Errorf("relativeSymlinkTarget(root, %q, %q) = %q, want %q", c.name, c.target, got, c.want)
		}
	}
}
