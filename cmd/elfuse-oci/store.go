// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/partial"
)

// An OCI image-layout on disk (image-spec v1.1.1), managed by
// go-containerregistry's layout package, where images coexist as manifest
// descriptors in one index.json keyed by digest.
//
// refs.json pins ref->manifest-digest beside it rather than inside it: the
// layout is keyed by digest alone, so nothing in the spec preserves the
// reference a pull was spelled with, and keeping the table separate leaves
// index.json parseable by any OCI reader.

const (
	ociLayoutFile = `{"imageLayoutVersion":"1.0.0"}`
	emptyIndex    = `{"schemaVersion":2,"manifests":[]}`
)

type store struct {
	path layout.Path
	root string
}

// Every reader and writer of the on-disk layout derives its paths here,
// so a layout change lands in one place.
func (s *store) indexPath() string { return filepath.Join(s.root, "index.json") }
func (s *store) pinsPath() string  { return filepath.Join(s.root, "refs.json") }
func (s *store) blobsDir() string  { return filepath.Join(s.root, "blobs") }
func (s *store) lockPath() string  { return filepath.Join(s.root, ".lock") }

// openStore ensures the layout scaffolding exists and returns a handle.
// The empty layout is created here rather than via layout.Write so the first
// pull goes through the same Append path as every subsequent one, under the
// store lock because writeIfAbsent's stat-then-write is check-then-act.
func openStore(root string) (*store, error) {
	s := &store{path: layout.Path(root), root: root}
	for _, d := range []string{root, s.blobsDir(), filepath.Join(s.blobsDir(), "sha256")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	layoutFile := filepath.Join(root, "oci-layout")
	indexFile := s.indexPath()
	// Fast path: both files are never removed once created, so a warm store
	// needs no lock and startup does not block behind a concurrent pull's
	// store lock; writeIfAbsent re-checks under the lock.
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
	return writeFileDurable(path, data, 0o644)
}

// writeFileDurable writes data via a fsynced temp sibling, renames it
// into place, then fsyncs the parent directory. Store metadata needs
// durability, not merely atomicity: recovery ordering (blobs and index
// durable before the pin, no pin reverting after a crash) only holds if
// every committed write survives. The layout package's plain
// os.WriteFile provides neither.
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
	return fsyncPath(dir)
}

// refPins maps an image reference to its pinned manifest digests
// ("sha256:..."), keyed by the platform string the pull requested
// ("os/arch[/variant]"). Platform belongs in the key: --platform invites
// pulling one ref for several platforms (arm64 native, amd64 under
// Rosetta), and a single pin per ref would let the second pull silently
// replace the first.
type refPins map[string]map[string]string

func (s *store) loadPins() (refPins, error) {
	b, err := os.ReadFile(s.pinsPath())
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
	for ref, byPlatform := range p {
		if byPlatform == nil {
			return nil, fmt.Errorf("store: corrupt refs.json: %q: expected object", ref)
		}
	}
	return p, nil
}

func (s *store) savePins(p refPins) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileDurable(s.pinsPath(), b, 0o644)
}

// fsyncPath flushes a path's own state: opened as a directory it commits
// the entries (renames, unlinks), opened as a file the data.
func fsyncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// syncImageBlobs fsyncs img's blobs, their directories, and the store
// root. It runs after the blob writes and before the index append and
// pin: index.json must never durably name blobs the page cache could
// still lose, and see writeFileDurable for why the pin must not commit
// before they are durable either.
func (s *store) syncImageBlobs(img v1.Image) error {
	digests, err := imageBlobDigests(img)
	if err != nil {
		return err
	}
	synced := map[string]bool{}
	for _, h := range digests {
		p := filepath.Join(s.blobsDir(), h.Algorithm, h.Hex)
		if err := fsyncPath(p); err != nil {
			return err
		}
		if synced[h.Algorithm] {
			continue
		}
		synced[h.Algorithm] = true
		// A blob's directory entry is durable only once the directory is
		// itself fsynced.
		if err := fsyncPath(filepath.Join(s.blobsDir(), h.Algorithm)); err != nil {
			return err
		}
	}
	if err := fsyncPath(s.blobsDir()); err != nil {
		return err
	}
	return fsyncPath(s.root)
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
// a pull racing a removal); without it, last-writer-wins on refs.json drops a
// just-recorded pin. Blob writes stay outside the lock: blobs are
// content-addressed, so concurrent writers land identical bytes, and the
// network-backed layer reads must not stall other processes' metadata
// updates.
func (s *store) lock() (func(), error) {
	// acquireFlock, not a bare Flock: see flock.go for the EINTR retry.
	l, err := acquireFlock(s.lockPath())
	if err != nil {
		return nil, fmt.Errorf("store: lock: %w", err)
	}
	return func() { _ = l.Close() }, nil
}

// withLock runs fn while holding the store lock.
func (s *store) withLock(fn func() error) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

func (s *store) pin(ref, platform, digest string) error {
	return s.withLock(func() error { return s.pinLocked(ref, platform, digest) })
}

// Caller holds the store lock.
func (s *store) pinLocked(ref, platform, digest string) error {
	p, err := s.loadPins()
	if err != nil {
		return err
	}
	if p[ref] == nil {
		p[ref] = map[string]string{}
	}
	p[ref][platform] = digest
	return s.savePins(p)
}

// errNotPulled marks the ref-simply-missing case, distinguishing it from
// store corruption or IO failures: an auto-pulling caller pulls only on
// this error, never over a corrupt store.
var errNotPulled = fmt.Errorf("not pulled")

// digestFor returns the manifest digest pinned for ref at platform, or an
// error wrapping errNotPulled if that pin is not in this store.
func (s *store) digestFor(ref string, platform Platform) (string, error) {
	p, err := s.loadPins()
	if err != nil {
		return "", err
	}
	d, ok := p[ref][platform.String()]
	if !ok {
		return "", fmt.Errorf("store: %q %w for %s (run `elfuse-oci pull --platform %s %s` first)",
			ref, errNotPulled, platform, platform, ref)
	}
	return d, nil
}

// addImage writes img's blobs, appends its manifest descriptor to the
// layout index if not already present (dedup by digest), and pins
// (ref, platform) to that digest. Returns the digest.
//
// Blob writes run outside the lock, since blobs are content-addressed and
// the layer transfer is network-bound, and they run whether or not the
// index already names the image, so a blob a crash or an operator lost is
// refetched instead of failing every later pull. The lock covers the
// check-append-pin read-modify-write of index.json.
func (s *store) addImage(ref string, platform Platform, img v1.Image) (string, error) {
	d, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("store: compute manifest digest: %w", err)
	}
	h, err := v1.NewHash(d.String())
	if err != nil {
		return "", err
	}
	if err := s.writeImageBlobs(img); err != nil {
		return "", err
	}
	if err := s.syncImageBlobs(img); err != nil {
		return "", fmt.Errorf("store: sync image blobs: %w", err)
	}
	desc, err := imageDescriptor(img)
	if err != nil {
		return "", err
	}
	err = s.withLock(func() error {
		present, err := s.hasImageLocked(h)
		if err != nil {
			return fmt.Errorf("store: read layout index: %w", err)
		}
		if !present {
			if err := s.appendIndexLocked(desc); err != nil {
				return err
			}
		}
		return s.pinLocked(ref, platform.String(), d.String())
	})
	if err != nil {
		return "", err
	}
	return d.String(), nil
}

// writeImageBlobs writes img's blobs into the store, unlocked: blobs are
// content-addressed, so concurrent writers land identical bytes. Config
// and manifest go through writeFileDurable, since the layout package's
// in-place write could leave a partial blob a later size check accepts.
// Layer blobs keep WriteImage, whose temp-and-rename write is atomic and
// whose skip of an existing blob is size-checked, so the durable copies
// stand and a truncated layer is refetched.
func (s *store) writeImageBlobs(img v1.Image) error {
	cfgHash, err := img.ConfigName()
	if err != nil {
		return err
	}
	cfgRaw, err := img.RawConfigFile()
	if err != nil {
		return err
	}
	manHash, err := img.Digest()
	if err != nil {
		return err
	}
	manRaw, err := img.RawManifest()
	if err != nil {
		return err
	}
	for _, b := range []struct {
		h   v1.Hash
		raw []byte
	}{{cfgHash, cfgRaw}, {manHash, manRaw}} {
		dir := filepath.Join(s.blobsDir(), b.h.Algorithm)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := writeFileDurable(filepath.Join(dir, b.h.Hex), b.raw, 0o644); err != nil {
			return fmt.Errorf("store: write blob: %w", err)
		}
	}
	if err := s.path.WriteImage(img); err != nil {
		return fmt.Errorf("store: write image: %w", err)
	}
	return nil
}

// imageDescriptor returns img's index descriptor with its platform filled
// in from the config: partial.Descriptor leaves Platform nil, and a store
// holding one ref at several platforms needs index.json to tell the
// manifests apart.
func imageDescriptor(img v1.Image) (*v1.Descriptor, error) {
	desc, err := partial.Descriptor(img)
	if err != nil {
		return nil, err
	}
	if desc.Platform == nil {
		cfg, err := img.ConfigFile()
		if err != nil {
			return nil, err
		}
		desc.Platform = &v1.Platform{
			OS:           cfg.OS,
			Architecture: cfg.Architecture,
			Variant:      cfg.Variant,
		}
	}
	return desc, nil
}

// appendIndexLocked appends desc to index.json; the caller holds the
// store lock and has already made desc's blobs durable. The index goes
// through writeFileDurable, not the layout package's in-place write: a
// crash there could leave a truncated index the store fails closed on
// forever.
func (s *store) appendIndexLocked(desc *v1.Descriptor) error {
	ii, err := s.path.ImageIndex()
	if err != nil {
		return err
	}
	im, err := ii.IndexManifest()
	if err != nil {
		return err
	}
	im.Manifests = append(im.Manifests, *desc)
	b, err := json.MarshalIndent(im, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileDurable(s.indexPath(), b, 0o644); err != nil {
		return fmt.Errorf("store: write index: %w", err)
	}
	return nil
}

// hasImageLocked reports whether the layout index already carries a manifest
// descriptor for h; the caller holds the store lock. A positive membership
// scan, not s.path.Image(h): the layout package's untyped error would read a
// corrupt index.json as "absent" and silently append into a broken store.
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

func (s *store) image(ref string, platform Platform) (v1.Image, error) {
	d, err := s.digestFor(ref, platform)
	if err != nil {
		return nil, err
	}
	h, err := v1.NewHash(d)
	if err != nil {
		return nil, err
	}
	return s.path.Image(h)
}
