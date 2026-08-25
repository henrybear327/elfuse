// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/continuity/fs"
)

// Special-mode bits in a tar header (setuid, setgid, sticky).
const tarSpecialBits = 0o4000 | 0o2000 | 0o1000

// clearSpecialBits names the host capability, not the OS: an
// unprivileged darwin chmod EPERMs on a foreign-group setgid file.
const clearSpecialBits = runtime.GOOS == "darwin"

// layerFilter adapts an image's entries for archive.Apply, which reads
// each header after the filter. One filter spans every layer, so a
// hardlink finds a target dropped from an earlier one; root is the tree
// being unpacked, consulted for symlinked parents. docs/oci-images.md
// "The Tar Filter" carries the rationale for each rewrite.
func layerFilter(root string) archive.Filter {
	// One warning per image, naming the first instance.
	warnedDev, warnedBits := false, false
	// Paths whose entry was dropped and not recreated since: a hardlink
	// to one drops too, or Apply's os.Link fails ENOENT and aborts the
	// layer.
	dropped := map[string]bool{}
	return func(hdr *tar.Header) (bool, error) {
		name := layerKey(hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			dropped[name] = true
			if !warnedDev {
				warnedDev = true
				fmt.Fprintf(os.Stderr, "elfuse-oci: unpack: dropping special files (first: %q); elfuse synthesizes /dev\n", hdr.Name)
			}
			// As a whiteout the entry still replaces a lower layer's file
			// at its path, and Apply writes nothing for it.
			hdr.Name = path.Join(path.Dir(name), ".wh."+path.Base(name))
			hdr.Typeflag = tar.TypeReg
			hdr.Size = 0
			return true, nil
		case tar.TypeLink:
			if dropped[layerKey(hdr.Linkname)] {
				dropped[name] = true
				return false, nil
			}
		}
		delete(dropped, name)
		if clearSpecialBits && hdr.Mode&tarSpecialBits != 0 {
			hdr.Mode &^= tarSpecialBits
			if !warnedBits {
				warnedBits = true
				fmt.Fprintf(os.Stderr, "elfuse-oci: unpack: clearing setuid/setgid/sticky bits (first: %q); unprivileged macOS unpack\n", hdr.Name)
			}
		}
		if hdr.Typeflag == tar.TypeSymlink && path.IsAbs(hdr.Linkname) {
			hdr.Linkname = relativeSymlinkTarget(root, hdr.Name, hdr.Linkname)
		}
		return true, nil
	}
}

// layerKey spells an entry name or link target root-relative, since Apply
// cleans Name but keeps its leading slash and leaves Linkname as is.
func layerKey(name string) string {
	return strings.TrimPrefix(path.Clean(name), "/")
}

// relativeSymlinkTarget rewrites an absolute target relative to the
// link's own directory, both taken root-relative: an entry name carrying
// a leading separator would otherwise make Rel fail and rewrite the link
// to its own directory. The directory is resolved through root as Apply
// places the entry, so a link under a symlinked parent (lib -> usr/lib)
// is relative to where it lands, not to its tar-name parent.
func relativeSymlinkTarget(root, name, target string) string {
	dir := strings.TrimPrefix(path.Dir(path.Clean(name)), "/")
	if root != "" {
		root = filepath.Clean(root)
		if phys, err := fs.RootPath(root, dir); err == nil {
			dir = strings.TrimPrefix(strings.TrimPrefix(phys, root), "/")
		}
	}
	if dir == "" {
		dir = "."
	}
	to := path.Clean(target)[1:]
	if to == "" {
		to = "."
	}
	rel, err := filepath.Rel(dir, to)
	if err != nil {
		return "."
	}
	return rel
}
