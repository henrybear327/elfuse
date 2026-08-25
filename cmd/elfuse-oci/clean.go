// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// cmdClean removes the store (with --cache, only its unpacked caches),
// then detaches bundle volumes orphaned by a store removed under them.
// Nothing guards live guests.
func cmdClean(args []string) error {
	if err := cleanStore(args); err != nil {
		return err
	}
	n, err := detachOrphanBundles()
	if n > 0 {
		fmt.Fprintf(os.Stderr, "Detached %d orphaned sparsebundle volume(s)\n", n)
	}
	return err
}

func cleanStore(args []string) error {
	cf, cacheOnly, rest, err := parseCommand(cleanFlagSet, args)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("clean: takes no <ref> argument")
	}
	if err := cf.resolveStore(); err != nil {
		return err
	}
	s := &store{root: cf.store}
	if _, err := os.Lstat(s.root); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Nothing to clean at %s\n", s.root)
		return nil
	}
	return s.withLock(context.Background(), func() error {
		// A mounted sparsebundle volume must detach before its bundle
		// directory goes, or the RemoveAll fails against the live mount.
		if err := detachStoreBundles(s); err != nil {
			return err
		}
		if *cacheOnly {
			for _, kind := range cacheKinds {
				if err := os.RemoveAll(filepath.Join(s.root, kind)); err != nil {
					return err
				}
			}
			fmt.Fprintf(os.Stderr, "Removed caches under %s\n", s.root)
			return nil
		}
		entries, err := os.ReadDir(s.root)
		if err != nil {
			return err
		}
		for _, e := range entries {
			// Removing the held lock file under a waiting acquirer would
			// orphan its flock.
			if e.Name() == ".lock" {
				continue
			}
			if err := os.RemoveAll(filepath.Join(s.root, e.Name())); err != nil {
				return err
			}
		}
		fmt.Fprintf(os.Stderr, "Removed store %s\n", s.root)
		return nil
	})
}

func cleanFlagSet(cf *commonFlags) (*flag.FlagSet, *bool) {
	fs := newCommandFlagSet("clean", cf)
	cacheOnly := fs.Bool("cache", false, "drop unpacked caches and sparsebundles but keep blobs and pins (orphaned bundle volumes are detached either way)")
	return fs, cacheOnly
}
