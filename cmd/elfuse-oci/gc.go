// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/v1"
)

// rmReport summarizes a reachability-GC pass: the blob digests removed (or that
// would be removed, under --dry-run) and the bytes reclaimed. CacheDropped
// records whether rmi also reclaimed the image's unpacked cache, so the command
// can report it rather than deleting a large warm tree silently.
type rmReport struct {
	Ref          string
	Blobs        []string
	Bytes        int64
	CacheDropped bool
}

// gc runs a reachability pass over the OCI image-layout store and removes any
// sha256 blob that is not reachable from an index.json manifest descriptor.
// Reachability follows manifest/index descriptors recursively, then marks image
// manifests, configs, and layers live. When dryRun is set, gc reports what it
// would reclaim and deletes nothing.
//
// gc is the shared engine behind `rmi` (called after a manifest descriptor is
// removed from index.json, so the dropped image's config/layers surface as
// unreachable) and `prune` (a standalone sweep that reclaims retag/partial-pull
// orphans). It also reclaims stale temporary blob files left by interrupted
// writes under blobs/sha256/; those filenames are not valid sha256 digests and
// make layout.Path.GarbageCollect abort before it can sweep anything.
//
// It first reconciles index.json against the pin set (pruneUnpinnedDescriptors)
// so a re-pulled mutable tag's orphaned prior descriptor stops keeping its
// blobs live; the blob sweep then reclaims them. A dry run reconciles nothing
// and reports against the current index.
func (s *store) gc(dryRun bool) (rmReport, error) {
	if !dryRun {
		if err := s.pruneUnpinnedDescriptors(); err != nil {
			return rmReport{}, fmt.Errorf("gc: reconcile descriptors: %w", err)
		}
	}
	live, err := s.liveBlobDigests()
	if err != nil {
		return rmReport{}, fmt.Errorf("gc: compute reachability: %w", err)
	}
	var rep rmReport
	blobs, err := s.localBlobFiles()
	if err != nil {
		return rep, err
	}
	for _, b := range blobs {
		if !b.malformed && live[b.digest] {
			continue
		}
		fi, err := os.Stat(b.path)
		if os.IsNotExist(err) {
			continue // raced or already removed
		}
		if err != nil {
			return rep, err
		}
		rep.Blobs = append(rep.Blobs, b.digest)
		rep.Bytes += fi.Size()
		if !dryRun {
			err := b.remove(s)
			if err != nil && !os.IsNotExist(err) {
				return rep, err
			}
		}
	}
	return rep, nil
}

type localBlob struct {
	path      string
	digest    string
	hash      v1.Hash
	malformed bool
}

func (b localBlob) remove(s *store) error {
	if b.malformed {
		return os.Remove(b.path)
	}
	return s.path.RemoveBlob(b.hash)
}

// liveBlobDigests roots reachability at the refs.json pin set, not at every
// index.json descriptor: an unpinned descriptor (a re-pulled tag's orphaned
// prior manifest, or a pull that appended a manifest but crashed before
// pinning) must not keep its blobs live. Each pinned digest's manifest,
// config, and layers are marked live. A real gc calls pruneUnpinnedDescriptors
// first so index.json never keeps referencing a manifest whose blobs this
// sweep reclaims; a dry run skips that but, rooting here at pins too, still
// reports exactly the blobs a real run would reclaim.
func (s *store) liveBlobDigests() (map[string]bool, error) {
	pins, err := s.loadPins()
	if err != nil {
		return nil, err
	}
	live := map[string]bool{}
	seen := map[string]bool{}
	for _, digest := range pins {
		if seen[digest] {
			continue // shared manifest already marked
		}
		seen[digest] = true
		h, err := v1.NewHash(digest)
		if err != nil {
			return nil, err
		}
		img, err := s.path.Image(h)
		if err != nil {
			return nil, fmt.Errorf("gc: read pinned manifest %s: %w", digest, err)
		}
		if err := markLiveImage(img, live); err != nil {
			return nil, err
		}
	}
	return live, nil
}

func markLiveImage(image v1.Image, live map[string]bool) error {
	h, err := image.Digest()
	if err != nil {
		return err
	}
	live[h.String()] = true

	h, err = image.ConfigName()
	if err != nil {
		return err
	}
	live[h.String()] = true

	layers, err := image.Layers()
	if err != nil {
		return err
	}
	for _, layer := range layers {
		h, err := layer.Digest()
		if err != nil {
			return err
		}
		live[h.String()] = true
	}
	return nil
}

func (s *store) localBlobFiles() ([]localBlob, error) {
	base := filepath.Join(s.root, "blobs", "sha256")
	entries, err := os.ReadDir(base)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	blobs := make([]localBlob, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			// The entry vanished between ReadDir and Info (a concurrent
			// rmi/prune already reclaimed it); skip it rather than aborting
			// the whole GC pass, matching the IsNotExist tolerance elsewhere
			// in this file.
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}

		name := e.Name()
		path := filepath.Join(base, name)
		if validSHA256Hex(name) {
			h := v1.Hash{Algorithm: "sha256", Hex: name}
			blobs = append(blobs, localBlob{path: path, digest: h.String(), hash: h})
			continue
		}
		blobs = append(blobs, localBlob{path: path, digest: "sha256:" + name, malformed: true})
	}
	return blobs, nil
}

func validSHA256Hex(s string) bool {
	return len(s) == 64 && isLowerHex(s)
}

// isLowerHex reports whether s contains only lowercase hex digits. Callers
// bound the length themselves (the empty string passes).
func isLowerHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// rewriteIndexManifests rewrites index.json to the descriptors keep returns
// true for, writing atomically and durably (writeFileDurable), not through the
// layout package's in-place os.WriteFile: rmi commits an index.json change
// before dropping the pin from refs.json, and that ordering only survives a
// crash if each write is individually durable. A plain truncate-in-place write
// could leave a torn index.json (store unreadable) or a non-durable change a
// crash reverts after the fsynced pin drop, stranding a descriptor and every
// blob it keeps live. It reports whether anything changed so callers can skip
// the write (and its fsync) when the index already matches.
func (s *store) rewriteIndexManifests(keep func(v1.Descriptor) bool) (bool, error) {
	idx, err := s.path.ImageIndex()
	if err != nil {
		return false, fmt.Errorf("rewrite index: read index: %w", err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return false, fmt.Errorf("rewrite index: parse index: %w", err)
	}
	kept := make([]v1.Descriptor, 0, len(im.Manifests))
	for _, desc := range im.Manifests {
		if keep(desc) {
			kept = append(kept, desc)
		}
	}
	if len(kept) == len(im.Manifests) {
		return false, nil
	}
	next := *im
	next.Manifests = kept
	b, err := json.Marshal(&next)
	if err != nil {
		return false, fmt.Errorf("rewrite index: marshal index: %w", err)
	}
	if err := writeFileDurable(filepath.Join(s.root, "index.json"), b, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// removeManifestDescriptor removes the manifest descriptor with the given digest
// from index.json. It does not touch the manifest's config or layer blobs; a
// subsequent gc pass reclaims them once they are unreachable from every
// remaining descriptor, so a blob shared with another still-pinned image is
// kept.
func (s *store) removeManifestDescriptor(digest string) error {
	h, err := v1.NewHash(digest)
	if err != nil {
		return fmt.Errorf("remove manifest descriptor: %w", err)
	}
	_, err = s.rewriteIndexManifests(func(desc v1.Descriptor) bool {
		return desc.Digest != h
	})
	return err
}

// pruneUnpinnedDescriptors removes index.json manifest descriptors that no
// refs.json pin references. Reachability GC roots liveness at index.json
// descriptors, so a re-pull that moves a mutable tag to a new digest would
// otherwise leak the prior image forever: its descriptor stays in the index
// (keeping every blob live) even though no ref pins it, and rmi cannot target
// a digest it can no longer resolve through a pin. Reconciling the index to
// the pin set before the blob sweep makes that orphan reclaimable. The store
// only ever appends single-platform image manifests (addImage), and pins point
// at them directly, so a top-level descriptor absent from the pin set is
// genuinely unreferenced.
func (s *store) pruneUnpinnedDescriptors() error {
	pins, err := s.loadPins()
	if err != nil {
		return err
	}
	pinned := make(map[string]bool, len(pins))
	for _, digest := range pins {
		pinned[digest] = true
	}
	_, err = s.rewriteIndexManifests(func(desc v1.Descriptor) bool {
		return pinned[desc.Digest.String()]
	})
	return err
}

// liveCacheKeys returns the set of digest cache keys for every currently pinned
// ref. pruneCaches uses it to keep digest-keyed rootfs/sparsebundle caches that
// are still reachable through refs.json.
func (s *store) liveCacheKeys() (map[string]bool, error) {
	pins, err := s.loadPins()
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(pins))
	for _, digest := range pins {
		key, err := cacheKeyForDigest(digest)
		if err != nil {
			return nil, err
		}
		m[key] = true
	}
	return m, nil
}

// rmi removes one selected ref from the store. The target may be an exact ref
// or a unique sha256 digest prefix. If other refs still pin the same manifest
// digest, only the resolved pin is dropped: the shared descriptor, blobs, and
// digest-keyed caches stay live through the remaining refs. If this was the last
// pin for the digest, rmi removes the manifest descriptor, GCs the
// now-unreachable blobs, and reclaims the image's unpacked cache: the cache is
// derived state subordinate to the image, so it goes with it instead of being
// left as an orphan only prune --cache could reap. Two safety rules survive
// force: a cache whose volume a live run still uses is never dropped (even with
// force), and a cache holding run --keep retained output refuses without force
// so a deliberate keep is not discarded silently.
func (s *store) rmi(target string, force bool) (rmReport, error) {
	// The store lock spans the whole resolve-modify-GC sequence so an rmi
	// cannot interleave with a concurrent pull's check-append-pin (or another
	// rmi) and lose one side's refs.json/index.json update.
	unlock, err := s.lock()
	if err != nil {
		return rmReport{}, err
	}
	defer unlock()
	pins, err := s.loadPins()
	if err != nil {
		return rmReport{}, err
	}
	ref, digest, err := resolvePinnedTarget(pins, target)
	if err != nil {
		return rmReport{}, err
	}

	lastPin := true
	for otherRef, otherDigest := range pins {
		if otherRef != ref && otherDigest == digest {
			lastPin = false
			break
		}
	}

	var cacheDropped bool
	if lastPin {
		// A live or starting run holds the digest's reference lock (the plain
		// rootfs run lock, taken by resolveImageForUse for every run path
		// before any cache dir or bundle exists). Probe it directly rather
		// than inferring liveness from cacheExists: a cold run that has
		// resolved the image but not yet unpacked has no cache to detect, yet
		// its descriptor and blobs must survive. rmi holds the store lock
		// throughout, and a run claims the reference lock only while holding
		// that same store lock (resolveImageForUse), so the set of holders is
		// frozen here: a busy probe cannot be a run that is about to appear.
		// Refuse regardless of force; force discards derived state, it does
		// not evict a running guest.
		rootfs, err := defaultRootfsForDigest(s.root, digest)
		if err != nil {
			return rmReport{}, err
		}
		if rootfsCacheBusy(rootfs) {
			return rmReport{}, fmt.Errorf("rmi: %q is in use by a live run; stop it before removing the image", ref)
		}
		// A run --keep clone is deliberately retained output living in the
		// cache; refuse to discard it without force. Everything else in the
		// cache is derived state reclaimed with the image below.
		kept, err := cacheHasKeptData(s.root, digest)
		if err != nil {
			return rmReport{}, fmt.Errorf("rmi: inspect cache for %q: %w", ref, err)
		}
		if kept && !force {
			return rmReport{}, fmt.Errorf("rmi: %q has retained run --keep output; pass --force to discard it, or inspect it with a fresh run then 'elfuse-oci prune --cache'", ref)
		}
		// Reclaim the unpacked cache as part of removing the image. removeRefCaches
		// fails closed if a live run still holds the volume (even with force), so
		// this never yanks a rootfs out from under a running guest.
		if cacheExists(s.root, digest) {
			if err := removeRefCaches(s, digest); err != nil {
				return rmReport{}, fmt.Errorf("rmi: drop cache for %q: %w", ref, err)
			}
			cacheDropped = true
		}
	}

	// On a last-pin removal, update index.json BEFORE committing the pin
	// removal to refs.json. In the opposite order, a failure between the two
	// writes strands the manifest: the ref is gone from refs.json (so rmi can
	// no longer resolve it) while the descriptor keeps every blob live, and
	// prune never removes descriptors; the image becomes unreclaimable. In
	// this order the same crash window leaves a stale pin over a removed
	// descriptor, which a retried rmi resolves and finishes
	// (RemoveDescriptors is a filter, so re-removing is a no-op).
	if lastPin {
		if err := s.removeManifestDescriptor(digest); err != nil {
			return rmReport{}, fmt.Errorf("rmi: remove manifest descriptor for %q: %w", ref, err)
		}
	}
	delete(pins, ref)
	if err := s.savePins(pins); err != nil {
		return rmReport{}, err
	}
	if !lastPin {
		return rmReport{Ref: ref}, nil
	}
	rep, err := s.gc(false)
	rep.Ref = ref
	rep.CacheDropped = cacheDropped
	return rep, err
}
