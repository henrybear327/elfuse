// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package main

import (
	"context"
	"fmt"
)

// csAvailable: the sparsebundle strategy needs macOS.
const csAvailable = false

// runCaseSensitive exists so the package compiles on Linux, where the
// offline tests run; cmdRun never dispatches here off darwin.
func runCaseSensitive(ctx context.Context, rc *runContext) error {
	return fmt.Errorf("case-sensitive sparsebundle rootfs requires macOS; pass --plain-rootfs for a plain directory")
}

// No sparsebundles exist off darwin: nothing to detach, nothing to sweep.
func detachStoreBundles(s *store) error { return nil }
func detachOrphanBundles() (int, error) { return 0, nil }
