// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1"
)

// rootfsStagingSuffix marks unpackImage's pre-rename staging siblings,
// <dest><suffix><random>. rootfsCacheLockPath parses it to map a staging
// dir back to its digest's lock, so the two must never drift apart.
const rootfsStagingSuffix = ".tmp-"

// unpackImage extracts every layer of img (base first) into a plain directory
// rootfs. Each layer is a tar stream (crane decompresses gzip and zstd
// transparently via layer.Uncompressed).
//
// img is the caller's already-resolved image, not a ref re-resolved here: the
// caller keys caches by the digest it resolved, and a re-resolution could
// observe a different pin (a concurrent repull) and fill a digest-keyed cache
// with another image's content.
//
// Layer application implements the OCI whiteout conventions:
//   - `.wh.<name>` in a directory removes `<name>` (from this and lower layers).
//   - `.wh..wh..opq` in a directory clears that directory's existing contents
//     before the layer's own additions are applied.
//
// Containment uses os.OpenRoot (Go 1.24+): every write is resolved relative
// to the rootfs and may not escape via ".." or a symlink. os.Root forbids
// absolute symlinks, so absolute symlink targets are rewritten to their
// equivalent relative form, which is behavior-preserving because under
// elfuse's --sysroot both forms resolve to the same guest path.
//
// Ownership is not applied here: elfuse runs as the host user and overrides
// identity at runtime via --user, so the rootfs carries only mode bits.
func unpackImage(img v1.Image, dest string) error {
	if _, statErr := os.Lstat(dest); statErr == nil {
		// An explicit pre-existing --rootfs directory: merge in place and
		// never remove it, failed or not; it is not ours to delete.
		return unpackInto(img, dest)
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	// The run paths treat the rootfs path's existence as "fully unpacked", so
	// a partial tree must never be visible under dest, not even while this
	// unpack is still running: a concurrent run probing dest with os.Stat
	// would execute against the half-written tree. Unpack into a temp sibling
	// (same volume, so the rename cannot degrade to a copy) and atomically
	// rename into place on success.
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dest), filepath.Base(dest)+rootfsStagingSuffix)
	if err != nil {
		return err
	}
	// MkdirTemp creates 0o700; the rootfs root must be traversable once
	// published.
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.RemoveAll(tmp)
		return err
	}
	if err := unpackInto(img, tmp); err != nil {
		os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.RemoveAll(tmp)
		if _, statErr := os.Lstat(dest); statErr == nil {
			// A concurrent unpack of the same image won the rename; its tree
			// is complete, so use it.
			return nil
		}
		return err
	}
	return nil
}

func unpackInto(img v1.Image, dest string) error {
	root, err := os.OpenRoot(dest)
	if err != nil {
		return fmt.Errorf("unpack: open rootfs %s: %w", dest, err)
	}
	defer root.Close()

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("unpack: list layers: %w", err)
	}
	for i, layer := range layers {
		if err := applyLayer(root, layer); err != nil {
			return fmt.Errorf("unpack: layer %d: %w", i, err)
		}
	}
	return nil
}

// layerPaths tracks what the current layer has created, so a late opaque
// whiteout does not wipe the layer's own additions. entries holds the exact tar
// entry paths; subtree additionally holds every ancestor directory of those
// entries, so an opaque clear can preserve an implicit parent directory the
// layer never gave its own tar entry (e.g. a layer with dir/sub/file but no
// dir/sub entry).
type layerPaths struct {
	entries map[string]bool
	subtree map[string]bool
}

func newLayerPaths() layerPaths {
	return layerPaths{entries: map[string]bool{}, subtree: map[string]bool{}}
}

// add records name as a current-layer entry and marks name and all its ancestor
// directories as carrying current-layer content.
func (lp layerPaths) add(name string) {
	lp.entries[name] = true
	for p := name; p != "." && p != string(filepath.Separator); {
		lp.subtree[p] = true
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
}

func applyLayer(root *os.Root, layer v1.Layer) error {
	r, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("open layer: %w", err)
	}
	defer r.Close()
	// Paths this layer has already created. Whiteouts hide lower-layer
	// content only, but tar entry order within a layer is not guaranteed: an
	// opaque marker may arrive after the directory's own same-layer children,
	// which must survive the clear (Docker's unpacker keeps the same set).
	lp := newLayerPaths()
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		if err := applyEntry(root, hdr, tr, lp); err != nil {
			return fmt.Errorf("entry %q: %w", hdr.Name, err)
		}
	}
}

// whiteoutPrefix is the OCI/Docker whiteout marker prefix.
const whiteoutPrefix = ".wh."

// opaqueMarker is the opaque-directory whiteout marker: a directory's
// existing children are hidden before the layer's own additions apply.
const opaqueMarker = whiteoutPrefix + ".wh..opq"

// rootRelative strips the leading slash from a cleaned tar path. Some
// builders (GNU tar -P) archive member names and hard-link targets absolute;
// OCI consumers apply both root-relative. Clean has already collapsed any
// ".." in an absolute path against the root, so dropping the slash cannot
// introduce an escape.
func rootRelative(cleaned string) string {
	return strings.TrimPrefix(cleaned, "/")
}

// applyEntry applies one tar header to the rootfs. lp tracks the paths the
// current layer has created so far, so an opaque whiteout arriving after its
// directory's same-layer children (or their implicit parents) does not delete
// them.
func applyEntry(root *os.Root, hdr *tar.Header, r io.Reader, lp layerPaths) error {
	name := filepath.Clean(hdr.Name)
	if strings.HasPrefix(name, "../") || name == ".." {
		return fmt.Errorf("unsafe entry path %q", hdr.Name)
	}
	name = rootRelative(name)
	if name == "" || name == "." {
		// The layer root itself; nothing to create.
		return nil
	}

	base := filepath.Base(name)
	if base == opaqueMarker {
		return clearDirectory(root, filepath.Dir(name), lp)
	}
	if trimmed, ok := strings.CutPrefix(base, whiteoutPrefix); ok {
		// A bare ".wh." would leave an empty target and Join(dir, "") is the
		// directory itself; a malformed layer must fail, not delete its
		// containing directory.
		if trimmed == "" {
			return fmt.Errorf("invalid whiteout entry %q", hdr.Name)
		}
		target := filepath.Join(filepath.Dir(name), trimmed)
		return root.RemoveAll(target)
	}
	lp.add(name)

	// hdr.FileInfo().Mode() maps the tar header's unix mode bits to os.FileMode
	// with the special bits (ModeSetuid/Setgid/Sticky) at os.FileMode's high
	// positions, not the raw unix positions. os.Root.MkdirAll/OpenFile reject
	// any non-permission bits, so split perm (0o777) from special bits and
	// re-apply special bits via Chmod (which syscallMode maps to the syscall).
	mode := hdr.FileInfo().Mode()
	perm := mode.Perm()
	special := mode & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	switch hdr.Typeflag {
	case tar.TypeDir:
		return mkdirAll(root, name, perm, special)
	case tar.TypeReg, tar.TypeRegA:
		if err := ensureParent(root, name); err != nil {
			return err
		}
		// Remove any prior entry (file, symlink, dir remnant) so we never
		// write through a symlink planted by a lower layer.
		_ = root.RemoveAll(name)
		f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
		if err != nil {
			return err
		}
		// Bound the copy to the header's declared size and require exactly
		// that many bytes. The tar reader normally guarantees both; enforcing
		// them here keeps the entry-size contract out of the caller's hands.
		n, err := io.Copy(f, io.LimitReader(r, hdr.Size))
		if err != nil {
			f.Close()
			return err
		}
		if n != hdr.Size {
			f.Close()
			return fmt.Errorf("entry body: read %d bytes, want %d", n, hdr.Size)
		}
		if err := f.Close(); err != nil {
			return err
		}
		return applyMode(root, name, perm, special)
	case tar.TypeSymlink:
		// makeSymlink runs ensureParent itself; no second walk here.
		return makeSymlink(root, name, hdr.Linkname, mode)
	case tar.TypeLink:
		if err := ensureParent(root, name); err != nil {
			return err
		}
		_ = root.RemoveAll(name)
		// A hard-link target names another member of the same rootfs; an
		// absolute target is applied root-relative like the member names
		// (the symlink path instead rewrites absolute targets, which
		// os.Root would reject here).
		return root.Link(rootRelative(filepath.Clean(hdr.Linkname)), name)
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		return fmt.Errorf("unsupported special file type %s", tarTypeName(hdr.Typeflag))
	default:
		return fmt.Errorf("unsupported tar type %d", hdr.Typeflag)
	}
}

func tarTypeName(t byte) string {
	switch t {
	case tar.TypeChar:
		return "char"
	case tar.TypeBlock:
		return "block"
	case tar.TypeFifo:
		return "fifo"
	default:
		return fmt.Sprintf("%d", t)
	}
}

// makeSymlink creates a symlink at name pointing to target. Absolute targets
// are rewritten to their equivalent relative form so os.Root accepts them
// (it rejects absolute symlinks); the relative form resolves to the same
// guest path under --sysroot, so this is behavior-preserving.
//
// Both name and target are guest paths. Clean an absolute target as a guest path
// first, then strip the leading "/" to make it rootfs-relative and compute the
// link-relative form with filepath.Rel (which needs both sides in the same
// form).
func makeSymlink(root *os.Root, name, target string, mode os.FileMode) error {
	if err := ensureParent(root, name); err != nil {
		return err
	}
	_ = root.RemoveAll(name)
	if filepath.IsAbs(target) {
		tgt := strings.TrimPrefix(filepath.Clean(target), string(filepath.Separator))
		if tgt == "" {
			tgt = "."
		}
		rel, err := filepath.Rel(filepath.Dir(name), tgt)
		if err != nil {
			return fmt.Errorf("rewrite absolute symlink %q: %w", target, err)
		}
		target = rel
	}
	if err := root.Symlink(target, name); err != nil {
		return err
	}
	// Symlink mode is not portable to set across platforms; ignore mode.
	_ = mode
	return nil
}

// ensureParent creates name's missing parent directories with the 0o755
// default. It never chmods: a parent that already exists may carry an exact
// mode from its own tar entry, which must not be reset to the default here.
//
// The walk Lstats every intermediate component instead of calling MkdirAll:
// a lower layer may have planted a symlink (or plain file) where this entry
// needs a directory, and MkdirAll would resolve through it, silently landing
// the entry in whatever the link points at; containment via os.Root still
// holds, but the file ends up in the wrong directory while the entry's own
// path stays unresolved. Replace any such component with a real directory,
// matching containerd's and Docker's unpackers.
func ensureParent(root *os.Root, name string) error {
	dir := filepath.Dir(name)
	if dir == "." {
		return nil
	}
	cur := ""
	for part := range strings.SplitSeq(dir, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		fi, err := root.Lstat(cur)
		if err == nil {
			if fi.IsDir() {
				continue
			}
			if err := root.RemoveAll(cur); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := root.Mkdir(cur, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return nil
}

// mkdirAll creates a directory entry and any missing parents, then finalizes
// the entry's own mode. os.Root.Mkdir rejects modes that carry
// setuid/setgid/sticky bits ("unsupported file mode"), so create with the
// permission bits only and finalize via applyMode. Parents go through
// ensureParent so lower-layer symlinks on the path are replaced, not
// traversed.
func mkdirAll(root *os.Root, name string, perm, special os.FileMode) error {
	if err := ensureParent(root, name); err != nil {
		return err
	}
	// A lower layer may have left a non-directory here, typically a symlink,
	// which Mkdir would otherwise resolve through, silently handing this
	// layer's children to whatever the link points at. Replace it with a real
	// directory, mirroring the RemoveAll the regular-file path does.
	if fi, err := root.Lstat(name); err == nil && !fi.IsDir() {
		if err := root.RemoveAll(name); err != nil {
			return err
		}
	}
	if err := root.Mkdir(name, perm); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return applyMode(root, name, perm, special)
}

// applyMode finalizes a just-created entry's mode to exactly perm|special.
// The chmod is unconditional: creation modes passed to os.Root.OpenFile and
// MkdirAll are masked by the process umask, so a restrictive host umask
// (e.g. 0077) would otherwise silently corrupt layer permissions. It also
// re-applies setuid/setgid/sticky, which os.Root creation methods reject at
// create time; Chmod -> syscallMode maps os.FileMode's high special-bit flags
// to the corresponding syscall bits.
//
// When the host cannot set the special bits, degrade to the plain permission
// bits rather than aborting the whole unpack. An unprivileged chmod that sets
// setuid/setgid is rejected with EPERM on macOS when the unpacked file's group
// is one the invoking user is not a member of: a new file inherits its parent
// directory's group (BSD semantics), e.g. wheel under /tmp, not the tar's
// root/shadow owner. The rootfs is owned by the invoking user, so these bits
// could not be honored at runtime on such a host regardless. Debian-family
// images (their shadow suite: chage, passwd, ...) would otherwise fail to
// unpack entirely.
func applyMode(root *os.Root, name string, perm, special os.FileMode) error {
	err := root.Chmod(name, perm|special)
	if shouldDropSpecial(err, special) {
		fmt.Fprintf(os.Stderr,
			"elfuse-oci: unpack: dropped %s on %q (unprivileged host)\n",
			specialBitNames(special), name)
		return root.Chmod(name, perm)
	}
	return err
}

// specialBitNames returns a "/"-joined list of the special mode bits present in
// mode (setuid, setgid, sticky), so the drop diagnostic names the bit actually
// lost instead of assuming setuid/setgid.
func specialBitNames(mode os.FileMode) string {
	var names []string
	if mode&os.ModeSetuid != 0 {
		names = append(names, "setuid")
	}
	if mode&os.ModeSetgid != 0 {
		names = append(names, "setgid")
	}
	if mode&os.ModeSticky != 0 {
		names = append(names, "sticky")
	}
	return strings.Join(names, "/")
}

// shouldDropSpecial reports whether a failed mode-finalizing chmod should be
// retried without the special bits. Only a permission error qualifies, and
// only when special bits were actually requested, so a genuine chmod failure
// (a permission error with no special bits, or any non-permission error) still
// surfaces to the caller unchanged.
func shouldDropSpecial(err error, special os.FileMode) bool {
	return err != nil && special != 0 && errors.Is(err, os.ErrPermission)
}

// clearDirectory removes the existing children of dir (opaque whiteout),
// keeping entries the current layer itself created: opaque markers hide
// lower-layer content, and a marker ordered after its directory's same-layer
// additions must not wipe them.
func clearDirectory(root *os.Root, dir string, lp layerPaths) error {
	fi, err := root.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// The marker's directory may be a symlink (or other non-dir) planted by a
	// lower layer. Reading through it would clear the link target's contents
	// (files the image author never whited out). Replace it with a real
	// empty directory instead: the opaque marker hides all lower content
	// under this name anyway, mirroring the non-dir replacement mkdirAll and
	// the regular-file path perform.
	if !fi.IsDir() {
		if lp.entries[dir] {
			// This layer created the non-dir itself; there is no lower
			// content beneath it for the marker to hide.
			return nil
		}
		if err := root.RemoveAll(dir); err != nil {
			return err
		}
		return root.Mkdir(dir, 0o755)
	}
	d, err := root.Open(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		child := filepath.Join(dir, e.Name())
		// Keep a child the current layer created OR that has current-layer
		// content beneath it: an implicit parent directory (dir/sub with no
		// own tar entry, created for dir/sub/file) has no entries[child] but is
		// in subtree, and deleting it would take the layer's own file with it.
		if lp.subtree[child] {
			continue
		}
		if err := root.RemoveAll(child); err != nil {
			return err
		}
	}
	return nil
}
