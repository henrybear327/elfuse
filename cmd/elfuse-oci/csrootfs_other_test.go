// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package main

import "testing"

// installFakeHdiutil has nothing to stub off darwin: no code path there
// runs hdiutil.
func installFakeHdiutil(t *testing.T) string { return "" }
