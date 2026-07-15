// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package main

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/v1"
)

// runCaseSensitive is the macOS case-sensitive sparsebundle + COW clone path.
// On non-Darwin there is no APFS/hdiutil/clonefile, and `run` is unusable
// anyway without Hypervisor.framework, so the default (case-sensitive) path
// reports a clear error and directs the user at --plain-rootfs. This stub
// exists so elfuse-oci compiles on Linux, where pull/inspect/unpack and
// conformance/interop tests run.
func runCaseSensitive(cf commonFlags, s *store, ref string, img v1.Image, digest string, cfg *v1.ConfigFile, rf runFlags, tail []string) error {
	return fmt.Errorf("case-sensitive sparsebundle rootfs requires macOS; pass --plain-rootfs for a plain directory")
}
