// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// pruneOpts controls a prune pass.
type pruneOpts struct {
	cache  bool // also drop elfuse rootfs/sparsebundle caches
	all    bool // with cache: drop caches even for still-pulled refs
	dryRun bool // report only; delete nothing
}

// pruneReport summarizes a prune pass: blobs reclaimed, cache dirs dropped,
// and the approximate bytes freed. The total mixes two accountings: blob
// bytes are logical file sizes, cache-dir bytes are on-disk allocation
// (st_blocks, the honest figure for sparse files and APFS clones), so it is
// an estimate, not one uniform metric.
type pruneReport struct {
	Blobs     []string
	CacheDirs []string
	Bytes     int64
}

// cmdPrune implements `elfuse-oci prune [--store] [--cache] [--all] [--dry-run]`.
//
// Without --cache, prune runs a reachability GC over blobs/sha256/ and reclaims
// any blob not reachable from an index.json manifest descriptor (retag or
// partial-pull orphans). With --cache it additionally drops elfuse's unpacked
// caches: the plain rootfs/<algo>/<hex> directories and, on darwin, the
// case-sensitive sparsebundle bundles (cs/<algo>/<hex>). By default only
// digest-keyed caches no longer reachable from refs.json are dropped, plus any
// legacy ref-named caches; --all drops every cache, including for still-pulled
// refs. --dry-run reports what would be removed without deleting. --all
// requires --cache (it has no meaning for the blob GC, which is already
// unconditional).
func cmdPrune(args []string) error {
	cf, opts, err := parsePruneArgs(args)
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}

	// The whole sweep runs under the store lock: the GC's reachability scan
	// must not race a concurrent pull, whose fresh blobs land before the
	// index descriptor that makes them reachable and would otherwise be
	// reclaimed in the window between the two writes. rmi already runs its
	// own gc under this lock. Reporting below happens after the lock drops.
	var rep pruneReport
	err = s.withLock(func() error {
		gcr, err := s.gc(opts.dryRun)
		if err != nil {
			return err
		}
		rep.Blobs = gcr.Blobs
		rep.Bytes += gcr.Bytes

		if opts.cache {
			cr, err := s.pruneCaches(opts)
			if err != nil {
				return err
			}
			rep.CacheDirs = cr.CacheDirs
			rep.Bytes += cr.Bytes
		}
		return nil
	})
	if err != nil {
		return err
	}

	verb := "Reclaimed"
	if opts.dryRun {
		verb = "Would reclaim"
	}
	fmt.Fprintf(os.Stderr, "%s: %d blob(s), %d cache dir(s), ~%d bytes\n",
		verb, len(rep.Blobs), len(rep.CacheDirs), rep.Bytes)
	for _, b := range rep.Blobs {
		fmt.Fprintf(os.Stderr, "  blob  %s\n", b)
	}
	for _, d := range rep.CacheDirs {
		fmt.Fprintf(os.Stderr, "  cache %s\n", d)
	}
	return nil
}

func parsePruneArgs(args []string) (commonFlags, pruneOpts, error) {
	var cf commonFlags
	var opts pruneOpts
	fs := newCommandFlagSet("prune", &cf)
	fs.BoolVar(&opts.cache, "cache", false, "also drop unpacked caches (rootfs/ and, on macOS, cs/ sparsebundles)")
	fs.BoolVar(&opts.all, "all", false, "with --cache, drop caches even for still-pulled refs")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "report what would be reclaimed without deleting")
	if err := fs.Parse(args); err != nil {
		return cf, opts, err
	}
	if err := noArgs("prune", fs.Args()); err != nil {
		return cf, opts, err
	}
	if opts.all && !opts.cache {
		return cf, opts, fmt.Errorf("prune: --all requires --cache")
	}
	return cf, opts, nil
}

// pruneRootfsCaches drops plain rootfs/<algo>/<hex> cache directories. Without
// opts.all, only dirs whose digest key is not live are dropped; with opts.all,
// every digest cache is dropped. Pre-digest rootfs/<legacy-ref-name> caches are
// always treated as orphaned legacy caches because they are no longer used by
// run/unpack. Shared across platforms; the darwin-only sparsebundle sweep lives
// in cache_darwin.go.
func pruneRootfsCaches(s *store, live map[string]bool, opts pruneOpts) (pruneReport, error) {
	var rep pruneReport
	base := filepath.Join(s.root, rootfsCacheDirName)
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return rep, nil
		}
		return rep, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		top := filepath.Join(base, e.Name())
		if e.Name() == "sha256" {
			children, err := os.ReadDir(top)
			if err != nil {
				return rep, err
			}
			for _, child := range children {
				if !child.IsDir() {
					continue
				}
				key := filepath.Join("sha256", child.Name())
				if !opts.all && live[key] {
					continue
				}
				dir := filepath.Join(top, child.Name())
				// A cache whose per-digest run lock is held belongs to a live
				// --plain-rootfs guest: skip it, and never advertise it in a
				// dry run, the way the bundle sweep skips a busy sparsebundle.
				// This also covers the non---all case where a re-pull moved
				// the pin off a digest a guest is still running from.
				if err := sweepPlainDir(&rep, dir, opts.dryRun); err != nil {
					return rep, err
				}
			}
			continue
		}

		// Legacy ref-named rootfs caches are no longer live under the
		// digest-keyed scheme; prune --cache reclaims them as orphan caches.
		// No run ever locks a legacy path, but the same locked removal keeps
		// one code path.
		if err := sweepPlainDir(&rep, top, opts.dryRun); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

// sweepPlainDir reclaims (or, in a dry run, reports) one plain rootfs cache
// dir, skipping it when a live --plain-rootfs guest holds its run lock, the
// way the bundle sweep skips a busy sparsebundle.
func sweepPlainDir(rep *pruneReport, dir string, dryRun bool) error {
	if dryRun {
		if rootfsCacheBusy(dir) {
			return nil
		}
		rep.Bytes += dirSize(dir)
		rep.CacheDirs = append(rep.CacheDirs, dir)
		return nil
	}
	size := dirSize(dir)
	if err := removeRootfsCache(dir); err != nil {
		if errors.Is(err, errCacheBusy) {
			return nil
		}
		return err
	}
	rep.Bytes += size
	rep.CacheDirs = append(rep.CacheDirs, dir)
	return nil
}

// dirSize reports the on-disk allocation (stat block count, not logical file
// size) of a tree, so a sparse APFS sparsebundle image is measured by the bytes
// it actually occupies rather than its 16g virtual ceiling. Best-effort: walk
// errors are ignored so a busy/evaporating entry does not abort the sweep.
func dirSize(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += diskUsage(info)
		}
		return nil
	})
	return total
}

// diskUsage returns the bytes actually allocated to a file (Blocks * 512) when
// the platform exposes stat blocks, falling back to logical size otherwise.
func diskUsage(fi os.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int64(st.Blocks) * 512
	}
	return fi.Size()
}
