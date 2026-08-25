// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// The store is a containerd local content store on disk (blobs/ and
// ingest/) plus refs.json beside it, pinning ref->manifest-digest per
// platform, since the content store carries no names. It is a cache:
// recovery from any corruption is elfuse-oci clean plus a re-pull.
type store struct {
	root    string
	content content.Store
}

// local.NewStore warns through logrus on every open that its fsverity
// check failed (it errors on non-Linux); only errors reach stderr.
func init() {
	log.SetLevel("error")
}

func openStore(root string) (*store, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	cs, err := local.NewStore(root)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", root, err)
	}
	return &store{root: root, content: cs}, nil
}

func (s *store) pinsPath() string { return filepath.Join(s.root, "refs.json") }
func (s *store) lockPath() string { return filepath.Join(s.root, ".lock") }

// The unpacked-cache namespaces under the store root, each holding
// sha256/<hex> slots keyed by manifest digest: plain rootfs trees and, on
// darwin, sparsebundles. clean, the inside-store refusals, and the cache
// fills agree on this layout.
const (
	cacheRootfs = "rootfs"
	cacheCS     = "cs"
)

var cacheKinds = []string{cacheRootfs, cacheCS}

func (s *store) cacheBase(kind string) string {
	return filepath.Join(s.root, kind, "sha256")
}

// digestHex validates a manifest digest for use as a cache key. Only
// sha256 digests mint keys; another algorithm would shape paths clean
// misreads.
func digestHex(dgst string) (string, error) {
	d, err := digest.Parse(dgst)
	if err != nil || d.Algorithm() != digest.SHA256 {
		return "", fmt.Errorf("store: unsupported digest %q for a cache key", dgst)
	}
	return d.Encoded(), nil
}

// cacheDir maps a manifest digest to its slot under kind. A symlink at
// a managed parent is refused, or a planted link would move a cache
// fill outside the store.
func (s *store) cacheDir(kind, dgst string) (string, error) {
	hex, err := digestHex(dgst)
	if err != nil {
		return "", err
	}
	for _, p := range []string{filepath.Join(s.root, kind), s.cacheBase(kind)} {
		if err := rejectSymlink(p, "use it as a cache directory"); err != nil {
			return "", err
		}
	}
	return filepath.Join(s.cacheBase(kind), hex), nil
}

// rejectSymlink errors when a symlink sits at path; an absent path passes.
func rejectSymlink(path, action string) error {
	li, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to %s", path, action)
	}
	return nil
}

// insideStore reports whether path is the store root or under it:
// symlinks resolved so a link cannot bypass the refusal, and case-folded
// because the store's usual home is case-insensitive APFS. An
// undecidable path reads as inside, the safe answer.
func insideStore(storeRoot, path string) bool {
	abs := resolvedAbs(path)
	absStore := resolvedAbs(storeRoot)
	if abs == "" || absStore == "" {
		return true
	}
	abs, absStore = strings.ToLower(abs), strings.ToLower(absStore)
	return abs == absStore || strings.HasPrefix(abs, absStore+string(filepath.Separator))
}

// resolvedAbs returns the symlink-resolved absolute form of path, or ""
// when that is undecidable. Components that do not exist yet ride on the
// longest existing prefix, resolved: EvalSymlinks fails on a missing
// leaf, and a fallback to the unresolved spelling would read a /var path
// as outside a /private/var store, or let a symlinked parent bypass the
// inside-store refusal.
func resolvedAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	rest := ""
	for p := abs; ; {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return abs
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}

// withLock runs fn while holding the store lock, which serializes whole
// pulls (the shared ingest/ directory and the refs.json read-modify-write)
// and clean against each other; nothing guards readers or live runs. The
// wait for the lock ends with ctx, so a pull's --timeout covers it.
func (s *store) withLock(ctx context.Context, fn func() error) error {
	l, err := acquireFlock(ctx, s.lockPath())
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer l.Close()
	return fn()
}

// refPins maps an image reference to its pinned manifest digests
// ("sha256:..."), keyed by the platform string the pull requested.
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
	// A malformed table must error rather than read as empty, or the
	// next save would erase every pin.
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

// savePins replaces refs.json atomically: readers hold no lock and must
// never see a truncated table.
func (s *store) savePins(p refPins) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return err
	}
	defer root.Close()
	return replaceFile(root, "refs.json", b)
}

// replaceFile writes name under root through a unique temp file and a
// rename, so a reader never sees a partial file and a symlink already at
// name is unlinked rather than followed.
func replaceFile(root *os.Root, name string, content []byte) error {
	tmp := fmt.Sprintf("%s.tmp.%d.%d", name, os.Getpid(), time.Now().UnixNano())
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		_ = root.Remove(tmp)
		return err
	}
	// Sync before the rename, or the name can outlive a crash while the
	// bytes do not.
	if err := f.Sync(); err != nil {
		f.Close()
		_ = root.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	return nil
}

// pinLocked records ref -> digest for platform; the caller holds the
// store lock (flock does not nest within one process).
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

// errNotPulled marks the ref-simply-missing case, so an auto-pulling
// caller pulls on it and never over a corrupt store.
var errNotPulled = fmt.Errorf("not pulled")

// digestFor returns the manifest digest pinned for ref at platform, or an
// error wrapping errNotPulled if that pin is not in this store.
func (s *store) digestFor(ref string, platform ocispec.Platform) (string, error) {
	p, err := s.loadPins()
	if err != nil {
		return "", err
	}
	key := platforms.Format(platform)
	d, ok := p[ref][key]
	if !ok {
		return "", fmt.Errorf("store: %q %w for %s (run `elfuse-oci pull --platform %s %s` first)",
			ref, errNotPulled, key, key, ref)
	}
	return d, nil
}

// loadRef resolves ref at platform to its pinned digest and manifest.
func (s *store) loadRef(ctx context.Context, ref string, platform ocispec.Platform) (string, ocispec.Manifest, error) {
	d, err := s.digestFor(ref, platform)
	if err != nil {
		return "", ocispec.Manifest{}, err
	}
	m, err := s.manifestFor(ctx, d)
	return d, m, err
}

// manifestFor loads the manifest pinned under dgst.
func (s *store) manifestFor(ctx context.Context, dgst string) (ocispec.Manifest, error) {
	var m ocispec.Manifest
	d, err := digest.Parse(dgst)
	if err != nil {
		return m, fmt.Errorf("store: manifest %s: %w", dgst, err)
	}
	b, err := content.ReadBlob(ctx, s.content, ocispec.Descriptor{Digest: d})
	if err != nil {
		return m, fmt.Errorf("store: read manifest %s: %w", dgst, err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("store: parse manifest %s: %w", dgst, err)
	}
	return m, nil
}

// configFor loads a manifest's config blob, raw and parsed: inspect
// --json emits the raw bytes verbatim, so fields the struct does not
// model survive.
func (s *store) configFor(ctx context.Context, m ocispec.Manifest) ([]byte, ocispec.Image, error) {
	var cfg ocispec.Image
	raw, err := content.ReadBlob(ctx, s.content, m.Config)
	if err != nil {
		return nil, cfg, fmt.Errorf("store: read config %s: %w", m.Config.Digest, err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, cfg, fmt.Errorf("store: parse config %s: %w", m.Config.Digest, err)
	}
	return raw, cfg, nil
}
