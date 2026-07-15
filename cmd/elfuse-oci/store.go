// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// The store is a real OCI image-layout on disk: an `oci-layout` version
// file, a `blobs/sha256/` tree, and an `index.json` image index (managed by
// go-containerregistry's layout package). Multiple pulled images coexist as
// separate manifest descriptors in the one index, distinguished by digest.
//
// On top of the spec layout we keep a ref->manifest-digest pin table
// (refs.json) so `unpack`/`inspect`/`run` can resolve an image by its
// original reference. This is elfuse-specific lookup metadata; OCI readers can
// still parse the layout through index.json and the content-addressed blobs.
// Keeping it separate lets us preserve the exact pull reference, including
// `docker.io/library/alpine:3` or `name@sha256:...`.

const (
	ociLayoutFile = `{"imageLayoutVersion":"1.0.0"}`
	emptyIndex    = `{"schemaVersion":2,"manifests":[]}`
)

type store struct {
	path layout.Path
	root string
}

// openStore ensures the layout scaffolding exists and returns a handle.
// Creating an empty layout (oci-layout + empty index.json + blobs/sha256/)
// here, rather than via layout.Write, lets the first pull go through the same
// Append path as every subsequent one. The bootstrap runs under the store
// lock: writeIfAbsent's stat-then-write is check-then-act, and without the
// lock a parallel first-use pull could rename an empty index.json over one
// that another process had just populated, leaving that process's pin
// pointing at a manifest the index no longer lists.
func openStore(root string) (*store, error) {
	for _, d := range []string{root, filepath.Join(root, "blobs"), filepath.Join(root, "blobs", "sha256")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	s := &store{path: layout.Path(root), root: root}
	layoutFile := filepath.Join(root, "oci-layout")
	indexFile := filepath.Join(root, "index.json")
	// Fast path: a warm store has both files, and they are never removed once
	// created, so no lock is needed. A run's startup must not block behind a
	// concurrent pull's store lock just to bootstrap no-ops; writeIfAbsent
	// re-checks under the lock, making this a double-checked bootstrap.
	if fileMissing(layoutFile) || fileMissing(indexFile) {
		err := s.withLock(func() error {
			if err := writeIfAbsent(layoutFile, []byte(ociLayoutFile)); err != nil {
				return err
			}
			return writeIfAbsent(indexFile, []byte(emptyIndex))
		})
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func fileMissing(path string) bool {
	_, err := os.Stat(path)
	return err != nil
}

// writeIfAbsent writes data to path unless the file already exists. The
// stat-then-write pair is check-then-act; the caller must hold the store
// lock so no metadata writer can slip between the two steps.
func writeIfAbsent(path string, data []byte) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	// Durable even on cold-store bootstrap: a crash mid-write must not leave a
	// truncated oci-layout or index.json that later opens fail to parse.
	return writeFileDurable(path, data, 0o644)
}

// writeFileDurable writes data to path atomically and durably: a uniquely
// named temp sibling is written, fsynced, and renamed into place, then the
// parent directory is fsynced so the rename itself survives a crash. A crash
// leaves either the prior file or the complete new one, never a truncated
// mix. This is the store's shared durability primitive for refs.json and
// index.json; rmi's crash-ordering rule (index.json committed before
// refs.json) holds only if each write is individually durable, which the
// layout package's plain os.WriteFile is not.
func writeFileDurable(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	// A unique temp name: a fixed name would let two writers clobber each
	// other's half-written temp even before the rename race.
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return fsyncDir(dir)
}

// refPins maps an image reference to its manifest digest ("sha256:...").
type refPins map[string]string

func (s *store) loadPins() (refPins, error) {
	b, err := os.ReadFile(filepath.Join(s.root, "refs.json"))
	if os.IsNotExist(err) {
		return refPins{}, nil
	} else if err != nil {
		return nil, err
	}
	var p refPins
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("store: corrupt refs.json: %w", err)
	}
	if p == nil {
		return nil, fmt.Errorf("store: corrupt refs.json: expected object")
	}
	return p, nil
}

func (s *store) savePins(p refPins) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	// Durability, not just atomicity: rmi's crash-ordering argument (commit the
	// index.json descriptor removal before dropping the pin) only holds if the
	// new refs.json cannot revert to an old pin after a crash.
	return writeFileDurable(filepath.Join(s.root, "refs.json"), b, 0o644)
}

// fsyncDir flushes a directory's entries (renames, unlinks) to stable
// storage.
func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// fsyncFile flushes an existing file's data to stable storage. Used to make a
// blob durable before the pin that references it is committed.
func fsyncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// syncAppendedImage makes img's on-disk state durable after AppendImage but
// before the pin is committed: the config and layer blobs, then index.json,
// then the store directory. Without this the pin (refs.json) is fsynced while
// the blobs and index it references may still sit in the page cache, so a
// crash could leave a durable pin over content that never reached disk, which
// every later resolve of the ref then fails on. The layout package writes
// blobs and index.json with plain os.WriteFile, so the durability is ours to
// add here.
func (s *store) syncAppendedImage(img v1.Image) error {
	digests, err := imageBlobDigests(img)
	if err != nil {
		return err
	}
	for _, h := range digests {
		p := filepath.Join(s.root, "blobs", h.Algorithm, h.Hex)
		if err := fsyncFile(p); err != nil {
			return err
		}
	}
	if err := fsyncFile(filepath.Join(s.root, "index.json")); err != nil {
		return err
	}
	return fsyncDir(s.root)
}

// imageBlobDigests returns the hashes of every blob img introduces: its
// manifest, config, and layers.
func imageBlobDigests(img v1.Image) ([]v1.Hash, error) {
	var hs []v1.Hash
	mh, err := img.Digest()
	if err != nil {
		return nil, err
	}
	hs = append(hs, mh)
	ch, err := img.ConfigName()
	if err != nil {
		return nil, err
	}
	hs = append(hs, ch)
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	for _, l := range layers {
		lh, err := l.Digest()
		if err != nil {
			return nil, err
		}
		hs = append(hs, lh)
	}
	return hs, nil
}

// lock takes an exclusive advisory flock on <root>/.lock and returns the
// unlock func. It serializes read-modify-write cycles on refs.json and
// index.json across concurrent elfuse-oci processes (parallel pulls, or
// a pull racing an rmi); without it, last-writer-wins on refs.json can drop a
// just-recorded pin.
func (s *store) lock() (func(), error) {
	// acquireFlock rather than a bare Flock: it retries EINTR (run's signal
	// forwarding can interrupt a blocking wait) and re-checks the lock file's
	// identity, one lock discipline for the whole package.
	l, err := acquireFlock(filepath.Join(s.root, ".lock"), syscall.LOCK_EX)
	if err != nil {
		return nil, fmt.Errorf("store: lock: %w", err)
	}
	return func() { _ = l.Close() }, nil
}

// withLock runs fn while holding the store lock. Results cross the closure
// boundary by capture; the lock is released before withLock returns, so
// callers can keep post-lock work (reporting, other stores) outside the
// critical section.
func (s *store) withLock(fn func() error) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// pin records ref->digest in the pin table.
func (s *store) pin(ref, digest string) error {
	return s.withLock(func() error { return s.pinLocked(ref, digest) })
}

// pinLocked is pin's load-modify-save cycle; the caller holds the store lock.
func (s *store) pinLocked(ref, digest string) error {
	p, err := s.loadPins()
	if err != nil {
		return err
	}
	p[ref] = digest
	return s.savePins(p)
}

// errNotPulled marks the ref-simply-missing case, distinguishing it from
// store corruption or IO failures: `run` auto-pulls only on this error.
var errNotPulled = fmt.Errorf("not pulled")

// digestFor returns the manifest digest pinned for ref, or an error wrapping
// errNotPulled if the ref has not been pulled into this store.
func (s *store) digestFor(ref string) (string, error) {
	p, err := s.loadPins()
	if err != nil {
		return "", err
	}
	d, ok := p[ref]
	if !ok {
		return "", fmt.Errorf("store: %q %w (run `elfuse-oci pull %s` first)", ref, errNotPulled, ref)
	}
	return d, nil
}

// resolvePinnedTarget resolves an exact pulled ref, or a unique sha256 digest
// prefix such as the 12-character digest printed by `list`.
func resolvePinnedTarget(pins refPins, target string) (string, string, error) {
	if d, ok := pins[target]; ok {
		return target, d, nil
	}

	prefix, ok := digestPrefix(target)
	if !ok {
		return "", "", fmt.Errorf("store: %q %w (run `elfuse-oci pull %s` first)", target, errNotPulled, target)
	}

	var matches []string
	matchDigest := ""
	for ref, digest := range pins {
		h, err := v1.NewHash(digest)
		if err != nil {
			return "", "", fmt.Errorf("store: pinned digest for %q: %w", ref, err)
		}
		if h.Algorithm == "sha256" && strings.HasPrefix(h.Hex, prefix) {
			matches = append(matches, ref)
			matchDigest = digest
		}
	}
	sort.Strings(matches)

	switch len(matches) {
	case 0:
		return "", "", fmt.Errorf("store: digest %q %w", target, errNotPulled)
	case 1:
		return matches[0], matchDigest, nil
	default:
		return "", "", fmt.Errorf("store: digest %q is ambiguous; matches refs: %s", target, strings.Join(matches, ", "))
	}
}

func digestPrefix(target string) (string, bool) {
	if i := strings.IndexByte(target, ':'); i >= 0 {
		if target[:i] != "sha256" {
			return "", false
		}
		target = target[i+1:]
	}
	target = strings.ToLower(target)
	if len(target) < 12 || len(target) > 64 || !isLowerHex(target) {
		return "", false
	}
	return target, true
}

// addImage appends img to the layout index if its manifest is not already
// present (dedup by digest), and pins ref to that digest. Returns the digest.
// The store lock covers the whole check-append-pin sequence: index.json is
// itself updated by read-modify-write inside the layout package, so two
// concurrent pulls could otherwise duplicate or drop descriptors.
func (s *store) addImage(ref string, img v1.Image) (string, error) {
	d, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("store: compute manifest digest: %w", err)
	}
	h, err := v1.NewHash(d.String())
	if err != nil {
		return "", err
	}
	err = s.withLock(func() error {
		// Re-pulling the same digest must not append a duplicate descriptor
		// to the index.
		present, err := s.hasImageLocked(h)
		if err != nil {
			return fmt.Errorf("store: read layout index: %w", err)
		}
		if !present {
			if err := s.path.AppendImage(img); err != nil {
				return fmt.Errorf("store: append image: %w", err)
			}
			// Make the blobs and index.json durable before the pin that will
			// point at them, so a crash never strands a fsynced pin over
			// content still in the page cache.
			if err := s.syncAppendedImage(img); err != nil {
				return fmt.Errorf("store: sync appended image: %w", err)
			}
		}
		return s.pinLocked(ref, d.String())
	})
	if err != nil {
		return "", err
	}
	return d.String(), nil
}

// hasImageLocked reports whether the layout index already carries a manifest
// descriptor for h. The caller holds the store lock. This is a positive
// membership scan rather than a probe via s.path.Image(h): the layout package
// returns an untyped error for both "not found" and a corrupt or unreadable
// index.json, and treating the latter as "absent" would silently append into
// a broken store, masking the corruption.
func (s *store) hasImageLocked(h v1.Hash) (bool, error) {
	ii, err := s.path.ImageIndex()
	if err != nil {
		return false, err
	}
	im, err := ii.IndexManifest()
	if err != nil {
		return false, err
	}
	for _, desc := range im.Manifests {
		if desc.Digest == h {
			return true, nil
		}
	}
	return false, nil
}

// image returns the v1.Image pinned for ref.
func (s *store) image(ref string) (v1.Image, error) {
	d, err := s.digestFor(ref)
	if err != nil {
		return nil, err
	}
	h, err := v1.NewHash(d)
	if err != nil {
		return nil, err
	}
	return s.path.Image(h)
}
