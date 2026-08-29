// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const tarSpecialBits = 0o4000 | 0o2000 | 0o1000

var clearSpecialBits = runtime.GOOS == "darwin"

type layerPolicy struct {
	root       string
	dropped    map[string]bool
	symlinks   map[string]string
	warnedNode bool
	warnedBits bool
}

func newLayerPolicy(root string) *layerPolicy {
	return &layerPolicy{
		root:     root,
		dropped:  make(map[string]bool),
		symlinks: make(map[string]string),
	}
}

func (p *layerPolicy) filter(hdr *tar.Header) bool {
	name := layerKey(hdr.Name)
	p.applyWhiteout(name)
	switch hdr.Typeflag {
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		p.dropped[name] = true
		delete(p.symlinks, name)
		if !p.warnedNode {
			p.warnedNode = true
			fmt.Fprintf(os.Stderr, "elfuse-oci: unpack: dropping device and FIFO entries (first: %q)\n", hdr.Name)
		}
		hdr.Name = path.Join(path.Dir(name), ".wh."+path.Base(name))
		hdr.Typeflag = tar.TypeReg
		hdr.Size = 0
		return true
	case tar.TypeLink:
		if p.dropped[layerKey(hdr.Linkname)] {
			p.dropped[name] = true
			delete(p.symlinks, name)
			return false
		}
	}
	delete(p.dropped, name)
	delete(p.symlinks, name)
	if clearSpecialBits && hdr.Mode&tarSpecialBits != 0 {
		hdr.Mode &^= tarSpecialBits
		if !p.warnedBits {
			p.warnedBits = true
			fmt.Fprintf(os.Stderr, "elfuse-oci: unpack: clearing special permission bits (first: %q)\n", hdr.Name)
		}
	}
	if hdr.Typeflag == tar.TypeSymlink {
		if path.IsAbs(hdr.Linkname) {
			if dir, resolved := p.resolveLayerPath(path.Dir(name)); resolved {
				hdr.Linkname = relativeTarget(dir, hdr.Linkname)
			} else {
				hdr.Linkname = relativeSymlinkTarget(p.root, hdr.Name, hdr.Linkname)
			}
		}
		p.symlinks[name] = hdr.Linkname
	}
	return true
}

func (p *layerPolicy) applyWhiteout(name string) {
	base := path.Base(name)
	if base == ".wh..wh..opq" {
		prefix := path.Dir(name) + "/"
		for link := range p.symlinks {
			if strings.HasPrefix(link, prefix) {
				delete(p.symlinks, link)
			}
		}
		return
	}
	if strings.HasPrefix(base, ".wh.") {
		delete(p.symlinks, path.Join(path.Dir(name), strings.TrimPrefix(base, ".wh.")))
	}
}

func filterLayer(src io.Reader, policy *layerPolicy) io.ReadCloser {
	r, w := io.Pipe()
	go func() {
		w.CloseWithError(writeFilteredLayer(w, src, policy))
	}()
	return r
}

func writeFilteredLayer(dst io.Writer, src io.Reader, policy *layerPolicy) error {
	tr := tar.NewReader(src)
	tw := tar.NewWriter(dst)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return tw.Close()
		}
		if err != nil {
			return err
		}
		if !policy.filter(hdr) {
			continue
		}
		// Rewrites may outgrow the source header's format.
		hdr.Format = tar.FormatUnknown
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return err
		}
	}
}

func layerKey(name string) string {
	return strings.TrimPrefix(path.Clean(name), "/")
}

func relativeSymlinkTarget(root, name, target string) string {
	dir := strings.TrimPrefix(path.Dir(path.Clean(name)), "/")
	if root != "" {
		root = resolvedAbs(root)
		candidate := resolvedAbs(filepath.Join(root, filepath.FromSlash(dir)))
		if rel, ok := pathWithin(root, candidate); ok {
			dir = filepath.ToSlash(rel)
		}
	}
	if dir == "" {
		dir = "."
	}
	return relativeTarget(dir, target)
}

func relativeTarget(dir, target string) string {
	to := strings.TrimPrefix(path.Clean(target), "/")
	if to == "" {
		to = "."
	}
	rel, err := filepath.Rel(filepath.FromSlash(dir), filepath.FromSlash(to))
	if err != nil {
		return "."
	}
	return filepath.ToSlash(rel)
}

func (p *layerPolicy) resolveLayerPath(name string) (string, bool) {
	name = layerKey(name)
	resolved := false
	for range 40 {
		parts := strings.Split(name, "/")
		prefix := ""
		for i, part := range parts {
			prefix = path.Join(prefix, part)
			target, ok := p.symlinks[prefix]
			if !ok {
				continue
			}
			resolved = true
			base := path.Dir(prefix)
			if path.IsAbs(target) {
				base = ""
			}
			name = path.Join(base, target)
			if i+1 < len(parts) {
				name = path.Join(name, path.Join(parts[i+1:]...))
			}
			break
		}
		if prefix == name {
			return name, resolved
		}
	}
	return name, resolved
}

func pathWithin(root, candidate string) (string, bool) {
	if root == "" || candidate == "" {
		return "", false
	}
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	if rel == "." {
		return "", true
	}
	return rel, true
}
