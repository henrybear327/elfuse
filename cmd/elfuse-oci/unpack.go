// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// cmdUnpack implements elfuse-oci unpack [--store] [--platform] [--rootfs] <ref>.
func cmdUnpack(args []string) error {
	cf, rootfs, ref, err := parseRefCommand("unpack", unpackFlagSet, args)
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	if err := refuseRootfsInStore("unpack", s.root, *rootfs); err != nil {
		return err
	}
	ctx := context.Background()
	d, m, err := s.loadRef(ctx, ref, cf.platform)
	if err != nil {
		return err
	}
	if *rootfs != "" {
		err = unpackImage(ctx, s, ref, m, *rootfs)
	} else {
		var dest string
		if dest, err = s.cacheDir(cacheRootfs, d); err == nil {
			err = ensureRootfs(ctx, s, ref, m, dest, true)
		}
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Unpacked %s\n", ref)
	return nil
}

// ensureRootfs fills a store-managed cache slot when cold; the publish
// rule (existence means fully unpacked, a symlink at the slot refused)
// lives here for every caller. reportWarm prints the line unpack owes
// its user; run stays silent on a warm cache.
func ensureRootfs(ctx context.Context, s *store, ref string, m ocispec.Manifest, dest string, reportWarm bool) error {
	published, err := storeRootfsPublished(dest)
	if err != nil {
		return err
	}
	if published {
		if reportWarm {
			fmt.Fprintf(os.Stderr, "Already unpacked %s -> %s\n", ref, dest)
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "Unpacking %s -> %s\n", ref, dest)
	return unpackImageFresh(ctx, s, m, dest)
}

func unpackFlagSet(cf *commonFlags) (*flag.FlagSet, *string) {
	fs := newCommandFlagSet("unpack", cf)
	addPlatformFlag(fs, cf)
	rootfs := fs.String("rootfs", "", "unpack into DIR instead of the store's digest-keyed cache")
	return fs, rootfs
}

// storeRootfsPublished reports whether a store-managed cache slot is
// published, refusing anything there but a real directory: a planted
// symlink would redirect extraction and the guest out of the store.
func storeRootfsPublished(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("rootfs cache %s is a symlink, refusing to use it", path)
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("rootfs cache %s is not a directory", path)
	}
	return true, nil
}

// unpackImage extracts into an explicit destination: an existing directory
// is merged in place and never removed (the directory is the user's), an
// absent one goes through the staging path.
func unpackImage(ctx context.Context, s *store, ref string, m ocispec.Manifest, dest string) error {
	fmt.Fprintf(os.Stderr, "Unpacking %s -> %s\n", ref, dest)
	exists, err := existingDirectory("unpack", dest)
	if err != nil {
		return err
	}
	if exists {
		return unpackInto(ctx, s, m, dest)
	}
	return unpackImageFresh(ctx, s, m, dest)
}

// existingDirectory reports whether path exists, refusing by name
// anything there but a directory: a symlink would be followed by
// archive.Apply and os.OpenRoot out of the tree the user named.
func existingDirectory(cmd, path string) (bool, error) {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("%s: %s is a %s, want a directory", cmd, path, fi.Mode().Type())
	}
	return true, nil
}

// unpackImageFresh stages in a sibling temp directory and renames, never
// merges: dest's existence means "fully unpacked" to every reader.
func unpackImageFresh(ctx context.Context, s *store, m ocispec.Manifest, dest string) error {
	// A trailing separator would put the staging directory inside dest
	// and the rename would then lose to it.
	dest = filepath.Clean(dest)
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, filepath.Base(dest)+".tmp-")
	if err != nil {
		return err
	}
	// MkdirTemp creates 0o700; a published rootfs root must be traversable.
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.RemoveAll(tmp)
		return err
	}
	if err := unpackInto(ctx, s, m, tmp); err != nil {
		os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.RemoveAll(tmp)
		// A concurrent unpack published first; anything else at dest is
		// the rename's error, not a winner.
		if published, pubErr := storeRootfsPublished(dest); published && pubErr == nil {
			return nil
		}
		return err
	}
	return nil
}

// unpackInto applies every layer base first through containerd's
// archive.Apply, without ownership (an unprivileged lchown to the
// image's uids fails) and through one layerFilter spanning the image.
func unpackInto(ctx context.Context, s *store, m ocispec.Manifest, dest string) error {
	filter := layerFilter(dest)
	for i, l := range m.Layers {
		if err := func() error {
			ra, err := s.content.ReaderAt(ctx, l)
			if err != nil {
				return err
			}
			defer ra.Close()
			dec, err := compression.DecompressStream(content.NewReader(ra))
			if err != nil {
				return err
			}
			defer dec.Close()
			_, err = archive.Apply(ctx, dest, dec, archive.WithNoSameOwner(),
				archive.WithFilter(filter))
			return err
		}(); err != nil {
			return fmt.Errorf("unpack: layer %d (%s): %w", i, l.Digest, err)
		}
	}
	return nil
}
