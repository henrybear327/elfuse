// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1"
)

// listEntry is one row of `elfuse-oci list --json`.
type listEntry struct {
	Ref      string `json:"ref"`
	Digest   string `json:"digest"`
	Platform string `json:"platform"`
	Created  string `json:"created,omitempty"`
	Size     int64  `json:"size"`
	Layers   int    `json:"layers"`
}

// list prints every ref pinned in the store with its manifest digest, platform,
// creation time, total compressed layer size, and layer count. With asJSON it
// emits a JSON array of listEntry; otherwise a human-readable table sorted by
// ref. The size is the sum of the layers' compressed descriptor sizes
// (layer.Size()), matching `docker images` and the blob bytes rmi or a plain
// prune would reclaim, not the uncompressed size, which would require
// streaming every layer and defeat a fast listing. (prune --cache reports a
// different pool entirely: the on-disk allocation of the unpacked caches.)
func list(w io.Writer, s *store, asJSON bool) error {
	// Snapshot pins and manifests under the store lock: a concurrent rmi
	// deletes both under the same lock, and reading unlocked could observe a
	// pin whose descriptor or blobs are already gone and fail mid-listing.
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	pins, err := s.loadPins()
	if err != nil {
		return err
	}
	refs := make([]string, 0, len(pins))
	for ref := range pins {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	entries := make([]listEntry, 0, len(refs))
	for _, ref := range refs {
		e := listEntry{Ref: ref, Digest: pins[ref]}
		h, err := v1.NewHash(pins[ref])
		if err != nil {
			return fmt.Errorf("list: %s: digest %q: %w", ref, pins[ref], err)
		}
		img, err := s.path.Image(h)
		if err != nil {
			return fmt.Errorf("list: %s: image: %w", ref, err)
		}
		cfg, err := img.ConfigFile()
		if err != nil {
			return fmt.Errorf("list: %s: config: %w", ref, err)
		}
		e.Platform = Platform{OS: cfg.OS, Arch: cfg.Architecture, Variant: cfg.Variant}.String()
		if !cfg.Created.IsZero() {
			e.Created = cfg.Created.UTC().Format("2006-01-02T15:04:05Z")
		}
		layers, err := img.Layers()
		if err != nil {
			return fmt.Errorf("list: %s: layers: %w", ref, err)
		}
		e.Layers = len(layers)
		for i, l := range layers {
			sz, err := l.Size()
			if err != nil {
				return fmt.Errorf("list: %s: layer %d size: %w", ref, i, err)
			}
			e.Size += sz
		}
		entries = append(entries, e)
	}

	if asJSON {
		b, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\n", b)
		return nil
	}
	if len(entries) == 0 {
		return nil
	}
	fmt.Fprintf(w, "%-40s  %-12s  %-14s  %12s  %s\n", "REF", "DIGEST", "PLATFORM", "SIZE", "LAYERS")
	for _, e := range entries {
		fmt.Fprintf(w, "%-40s  %s  %-14s  %12d  %d\n", e.Ref, shortDigest(e.Digest), e.Platform, e.Size, e.Layers)
	}
	return nil
}

// shortDigest returns the first 12 hex characters of a "sha256:..." digest.
func shortDigest(d string) string {
	if i := strings.Index(d, ":"); i >= 0 {
		d = d[i+1:]
	}
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// cmdList implements `elfuse-oci list [--store] [--json]` (alias: images).
func cmdList(args []string) error {
	cf, asJSON, err := parseListArgs(args)
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	return list(os.Stdout, s, asJSON)
}

func parseListArgs(args []string) (commonFlags, bool, error) {
	var cf commonFlags
	var asJSON bool
	fs := newCommandFlagSet("list", &cf)
	fs.BoolVar(&asJSON, "json", false, "emit a JSON array of {ref,digest,platform,created,size,layers}")
	if err := fs.Parse(args); err != nil {
		return cf, false, err
	}
	if err := noArgs("list", fs.Args()); err != nil {
		return cf, false, err
	}
	return cf, asJSON, nil
}
