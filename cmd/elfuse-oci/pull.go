// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1"
)

func platformOption(cf commonFlags) crane.Option {
	p := v1.Platform{
		OS:           cf.platform.OS,
		Architecture: cf.platform.Arch,
		Variant:      cf.platform.Variant,
	}
	return crane.WithPlatform(&p)
}

// checkImagePlatform rejects an image whose config disagrees with the
// requested platform. crane.WithPlatform selects a platform only for a
// ref that resolves to a manifest list; a single-manifest ref yields
// whatever the registry serves, past parsePlatform's linux gate. The
// variant is compared only when the request named one, since most
// configs leave it empty.
func checkImagePlatform(want Platform, img v1.Image) error {
	cfg, err := img.ConfigFile()
	if err != nil {
		return err
	}
	if cfg.OS != want.OS || cfg.Architecture != want.Arch ||
		(want.Variant != "" && cfg.Variant != want.Variant) {
		got := Platform{OS: cfg.OS, Arch: cfg.Architecture, Variant: cfg.Variant}
		return fmt.Errorf("image is %s, want %s", got, want)
	}
	return nil
}

// pullImage fetches ref from a registry into the store, pinning
// (ref, platform) to the image's manifest digest. Re-pulling the same
// digest is a no-op on the layout index (dedup by digest); only the pin
// table is refreshed. ctx bounds the whole transfer: crane's lazy image
// downloads layers inside the store's blob writes, so without it a hung
// registry would stall the pull forever.
func pullImage(ctx context.Context, cf commonFlags, s *store, ref string) error {
	// Progress goes to stderr, keeping stdout reserved for command output
	// that callers capture. Printed before the pull so a slow or
	// credential-blocked registry is not silent.
	fmt.Fprintf(os.Stderr, "Pulling %s...\n", ref)

	// Wrap the ambient keychain so a wedged credential helper fails fast with
	// an explanation instead of hanging the pull; see timedKeychain.
	keychain := crane.WithAuthFromKeychain(
		timedKeychain{authn.DefaultKeychain, credResolveTimeout})
	img, err := crane.Pull(ref, crane.WithContext(ctx), platformOption(cf), keychain)
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	if err := checkImagePlatform(cf.platform, img); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	digest, err := s.addImage(ref, cf.platform, img)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Pulled %s -> %s\n", ref, digest)
	return nil
}
