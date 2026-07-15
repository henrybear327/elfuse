// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1"
)

var cranePull = crane.Pull

// platformOption converts the parsed --platform into a crane option.
func platformOption(cf commonFlags) crane.Option {
	p := v1.Platform{
		OS:           cf.platform.OS,
		Architecture: cf.platform.Arch,
		Variant:      cf.platform.Variant,
	}
	return crane.WithPlatform(&p)
}

// pullImage fetches ref from a registry into the store, pinning ref to the
// image's manifest digest. Re-pulling the same digest is a no-op on the
// layout index (dedup by digest); only the pin table is refreshed.
func pullImage(cf commonFlags, s *store, ref string) error {
	// Progress goes to stderr: pullImage also runs on the `run` path, where
	// stdout belongs to the guest and callers capture it ($(run ...)). Printed
	// before the pull so a slow or credential-blocked registry is not silent.
	fmt.Fprintf(os.Stderr, "Pulling %s...\n", ref)

	// Wrap the ambient keychain so a wedged credential helper fails fast with
	// an explanation instead of hanging the pull; see timedKeychain.
	keychain := crane.WithAuthFromKeychain(
		timedKeychain{authn.DefaultKeychain, credResolveTimeout})
	img, err := cranePull(ref, platformOption(cf), keychain)
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	digest, err := s.addImage(ref, img)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Pulled %s -> %s\n", ref, digest)
	return nil
}
