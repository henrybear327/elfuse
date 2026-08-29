// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/go-archive"
	"github.com/moby/go-archive/compression"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type unpackCommand struct {
	commonFlags
	Rootfs string `help:"Unpack into this directory instead of the managed cache" type:"path"`
	Ref    string `arg:"" name:"ref" help:"Stored image reference"`
}

func (c *unpackCommand) Run() error {
	s, platform, err := c.commonFlags.openStore()
	if err != nil {
		return err
	}
	if err := refuseRootfsInStore("unpack", s.root, c.Rootfs); err != nil {
		return err
	}
	ctx := context.Background()
	digest, manifest, err := s.loadRef(ctx, c.Ref, platform)
	if err != nil {
		return err
	}
	if c.Rootfs != "" {
		err = unpackImage(ctx, s, c.Ref, manifest, c.Rootfs)
	} else {
		var dest string
		if dest, err = s.cacheDir(cacheRootfs, digest); err == nil {
			err = ensureRootfs(ctx, s, c.Ref, manifest, dest, true)
		}
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Unpacked %s\n", c.Ref)
	return nil
}

func ensureRootfs(ctx context.Context, s *store, ref string, manifest ocispec.Manifest, dest string, reportWarm bool) error {
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
	return unpackImageFresh(ctx, s, manifest, dest)
}

func storeRootfsPublished(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("rootfs cache %s is a symlink", path)
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("rootfs cache %s is not a directory", path)
	}
	return true, nil
}

func unpackImage(ctx context.Context, s *store, ref string, manifest ocispec.Manifest, dest string) error {
	fmt.Fprintf(os.Stderr, "Unpacking %s -> %s\n", ref, dest)
	exists, err := existingDirectory("unpack", dest)
	if err != nil {
		return err
	}
	if exists {
		return unpackInto(ctx, s, manifest, dest)
	}
	return unpackImageFresh(ctx, s, manifest, dest)
}

func existingDirectory(cmd, path string) (bool, error) {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("%s: %s is a %s, want a directory", cmd, path, fi.Mode().Type())
	}
	return true, nil
}

func unpackImageFresh(ctx context.Context, s *store, manifest ocispec.Manifest, dest string) error {
	dest = filepath.Clean(dest)
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, filepath.Base(dest)+".tmp-")
	if err != nil {
		return err
	}
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.RemoveAll(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	if err := unpackInto(ctx, s, manifest, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		if published, pubErr := storeRootfsPublished(dest); published && pubErr == nil {
			return nil
		}
		return err
	}
	removeTmp = false
	return nil
}

func unpackInto(ctx context.Context, s *store, manifest ocispec.Manifest, dest string) error {
	policy := newLayerPolicy(dest)
	options := &archive.TarOptions{NoLchown: true, BestEffortXattrs: true}
	for i, layer := range manifest.Layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		hash, err := v1.NewHash(layer.Digest.String())
		if err != nil {
			return fmt.Errorf("unpack: layer %d (%s): %w", i, layer.Digest, err)
		}
		blob, err := s.blob(hash)
		if err != nil {
			return fmt.Errorf("unpack: layer %d (%s): %w", i, layer.Digest, err)
		}
		err = applyLayer(dest, blob, policy, options)
		if closeErr := blob.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return fmt.Errorf("unpack: layer %d (%s): %w", i, layer.Digest, err)
		}
	}
	return nil
}

func applyLayer(dest string, blob io.Reader, policy *layerPolicy, options *archive.TarOptions) error {
	decompressed, err := compression.DecompressStream(blob)
	if err != nil {
		return err
	}
	defer decompressed.Close()
	filtered := filterLayer(decompressed, policy)
	defer filtered.Close()
	_, err = archive.ApplyUncompressedLayer(dest, filtered, options)
	return err
}
