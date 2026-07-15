// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

// cmdRmi implements `elfuse-oci rmi [--store] [--force] <ref|digest>`.
//
// rmi drops the selected ref's pin. The target may be an exact ref or a unique
// sha256 digest prefix from `list`. If no remaining ref pins the same manifest
// digest, it removes that descriptor from index.json, garbage-collects the
// now-unreachable blobs, and reclaims the image's unpacked cache (rootfs/ or cs/
// sparsebundle); the cache is derived state that goes with the image. A blob,
// descriptor, or cache still reachable through another pinned ref is kept. rmi
// refuses when a live run still uses the cache (never overridable) or when the
// cache holds run --keep retained output (then --force discards it). An absent
// ref/digest is an error.
func cmdRmi(args []string) error {
	cf, force, ref, err := parseRmiArgs(args)
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	rep, err := s.rmi(ref, force)
	if err != nil {
		return err
	}
	removed := ref
	if rep.Ref != "" {
		removed = rep.Ref
	}
	fmt.Fprintf(os.Stderr, "Removed %s: %d blob(s), %d bytes\n", removed, len(rep.Blobs), rep.Bytes)
	for _, b := range rep.Blobs {
		fmt.Fprintf(os.Stderr, "  blob %s\n", b)
	}
	if rep.CacheDropped {
		fmt.Fprintf(os.Stderr, "  dropped unpacked cache\n")
	}
	return nil
}

func parseRmiArgs(args []string) (commonFlags, bool, string, error) {
	var cf commonFlags
	var force bool
	fs := newCommandFlagSet("rmi", &cf)
	fs.BoolVar(&force, "force", false, "discard run --keep retained output when removing an image that has it")
	if err := fs.Parse(args); err != nil {
		return cf, false, "", err
	}
	ref, err := oneArg("rmi", fs.Args(), "<ref|digest>")
	return cf, force, ref, err
}
