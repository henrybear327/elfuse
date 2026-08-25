// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// cmdPull implements elfuse-oci pull [--store] [--platform] [--timeout] <ref>.
func cmdPull(args []string) error {
	cf, timeout, ref, err := parseRefCommand("pull", pullFlagSet, args)
	if err != nil {
		return err
	}
	if *timeout < 0 {
		return fmt.Errorf("pull: --timeout %s is negative (0 = no limit)", *timeout)
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}
	_, err = pullImage(ctx, cf, s, ref)
	return err
}

// --timeout bounds the whole pull, since a hung registry has no other
// limit; 0 (the default) is unbounded, as any fixed bound would fail
// large images on slow links.
func pullFlagSet(cf *commonFlags) (*flag.FlagSet, *time.Duration) {
	fs := newCommandFlagSet("pull", cf)
	addPlatformFlag(fs, cf)
	timeout := fs.Duration("timeout", 0, "fail the pull after this duration (0 = no limit)")
	return fs, timeout
}

// normalizeRef expands a Docker-style short reference the way docker
// does: "alpine:3" becomes "docker.io/library/alpine:3", and a ref with
// neither tag nor digest gets :latest.
func normalizeRef(ref string) (string, error) {
	named, err := reference.ParseDockerRef(ref)
	if err != nil {
		return "", err
	}
	return named.String(), nil
}

// newResolver returns the registry resolver: containerd's default hosts
// and token auth fed by the ambient docker config.
func newResolver() remotes.Resolver {
	authorizer := docker.NewDockerAuthorizer(docker.WithAuthCreds(dockerCredentials))
	return docker.NewResolver(docker.ResolverOptions{
		Hosts: docker.ConfigureDefaultRegistries(docker.WithAuthorizer(authorizer)),
	})
}

// The walk is containerd's own pull plus selectManifest's check of a
// bare manifest's config. Fetch and pin run under the store lock: two
// pulls of one blob would share one ingest.
func pullImage(ctx context.Context, cf commonFlags, s *store, ref string) (string, error) {
	name, err := normalizeRef(ref)
	if err != nil {
		return "", fmt.Errorf("pull %s: %w", ref, err)
	}

	// Progress goes to stderr, before the pull so a slow or
	// credential-blocked registry is not silent.
	fmt.Fprintf(os.Stderr, "Pulling %s...\n", ref)

	resolver := newResolver()
	name, desc, err := resolver.Resolve(ctx, name)
	if err != nil {
		return "", fmt.Errorf("pull %s: %w", ref, err)
	}
	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return "", fmt.Errorf("pull %s: %w", ref, err)
	}
	matcher := platforms.OnlyStrict(cf.platform)
	var manifest ocispec.Descriptor
	err = s.withLock(ctx, func() error {
		handler := images.Handlers(remotes.FetchHandler(s.content, fetcher),
			platformChildren(s.content, matcher))
		if err := images.Dispatch(ctx, handler, nil, desc); err != nil {
			return fmt.Errorf("pull %s: %w", ref, err)
		}
		m, err := selectManifest(ctx, s.content, desc, matcher)
		if err != nil {
			return fmt.Errorf("pull %s: %w", ref, err)
		}
		manifest = m
		return s.pinLocked(ref, platforms.Format(cf.platform), manifest.Digest.String())
	})
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "Pulled %s -> %s\n", ref, manifest.Digest)
	return manifest.Digest.String(), nil
}

// platformChildren is the pull's children handler: an index yields only
// its best match for the platform, a manifest its config and layers.
func platformChildren(cs content.Store, m platforms.MatchComparer) images.HandlerFunc {
	return images.LimitManifests(images.FilterPlatforms(images.ChildrenHandler(cs), m), m, 1)
}

// selectManifest returns the manifest to pin: the index child
// platformChildren chose, or a bare manifest, either one checked against
// its own config when the descriptor states no platform.
func selectManifest(ctx context.Context, cs content.Store, desc ocispec.Descriptor, m platforms.MatchComparer) (ocispec.Descriptor, error) {
	if images.IsIndexType(desc.MediaType) {
		children, err := platformChildren(cs, m)(ctx, desc)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		// FilterPlatforms keeps a child stating no platform and
		// LimitManifests only sorts those last, so one reaches the front
		// when it is the sole survivor. Read its config rather than pin
		// it on the index's word.
		if children[0].Platform != nil {
			return children[0], nil
		}
		return checkConfigPlatform(ctx, cs, children[0], m)
	}
	if !images.IsManifestType(desc.MediaType) {
		return ocispec.Descriptor{}, fmt.Errorf("unexpected media type %s: %w", desc.MediaType, errdefs.ErrNotFound)
	}
	return checkConfigPlatform(ctx, cs, desc, m)
}

// checkConfigPlatform returns desc once the platform in its config
// matches the request.
func checkConfigPlatform(ctx context.Context, cs content.Store, desc ocispec.Descriptor, m platforms.MatchComparer) (ocispec.Descriptor, error) {
	cfg, err := images.Config(ctx, cs, desc, nil)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	p, err := images.ConfigPlatform(ctx, cs, cfg)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	if !m.Match(p) {
		return ocispec.Descriptor{}, fmt.Errorf("manifest %s is %s: %w", desc.Digest, platforms.Format(p), errdefs.ErrNotFound)
	}
	return desc, nil
}
