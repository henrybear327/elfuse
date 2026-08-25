// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"testing"
)

// A command dispatched without --store resolves $ELFUSE_OCI_STORE, so the
// whole test process runs against a throwaway store. os.Exit skips
// defers, so the sandbox is removed by hand.
func TestMain(m *testing.M) {
	sandbox := ""
	if os.Getenv("ELFUSE_OCI_STORE") == "" {
		dir, err := os.MkdirTemp("", "elfuse-oci-test-store-")
		if err != nil {
			panic(err)
		}
		sandbox = dir
		os.Setenv("ELFUSE_OCI_STORE", dir)
	}
	code := m.Run()
	if sandbox != "" {
		if err := os.RemoveAll(sandbox); err != nil {
			fmt.Fprintf(os.Stderr, "elfuse-oci test: sandbox store left behind: %v\n", err)
		}
	}
	os.Exit(code)
}
