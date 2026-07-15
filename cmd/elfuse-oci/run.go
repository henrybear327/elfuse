// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

var execElfuseForRun = execElfuse

// elfuseBin locates the elfuse binary to exec for `run`. Precedence:
//   - $ELFUSE_BIN (an override hook for tests and wrapper scripts);
//   - the sibling of this executable (build/elfuse-oci -> build/elfuse).
func elfuseBin() (string, error) {
	if p := os.Getenv("ELFUSE_BIN"); p != "" {
		return p, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate elfuse: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), "elfuse"), nil
}

// execElfuse replaces this process with `elfuse --sysroot <rootfs> --user U:G
// --workdir D --clear-env --env K=V ... <entrypoint> <args>`.
//
// --clear-env plus every final env var as an explicit --env makes the guest
// see exactly the runspec env (image Env merged with --env overrides, per the
// precedence matrix) rather than the host environ.
//
// syscall.Exec replaces elfuse-oci in place: the invoking shell reaps
// the same pid, and signals such as Ctrl-C go straight to elfuse rather than
// through a Go middleman.
func execElfuse(rootfs string, spec *runSpec) error {
	bin, err := elfuseBin()
	if err != nil {
		return err
	}
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("elfuse binary not found at %s (set $ELFUSE_BIN): %w", bin, err)
	}

	argv := []string{
		"elfuse",
		"--sysroot", rootfs,
		"--user", fmt.Sprintf("%d:%d", spec.UID, spec.GID),
		"--workdir", spec.Workdir,
		"--clear-env",
	}
	for _, e := range spec.Env {
		argv = append(argv, "--env", e)
	}
	argv = append(argv, spec.Args...)

	if err := syscall.Exec(bin, argv, os.Environ()); err != nil {
		return fmt.Errorf("exec %s: %w", bin, err)
	}
	return nil // unreachable
}
