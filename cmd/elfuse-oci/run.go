// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
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

// elfuseArgv builds the argv for `elfuse --sysroot <rootfs> --user U:G
// --workdir D --clear-env --env K=V ... -- <entrypoint> <args>`.
//
// --clear-env plus every final env var as an explicit --env makes the guest see
// exactly the runspec env (image Env merged with --env overrides, per the
// precedence matrix) rather than the host environ.
//
// "--" ends elfuse's own option parsing: spec.Args comes from untrusted image
// config, so an Entrypoint beginning with "-" must reach the guest as its
// argv, not steer the host launcher (e.g. an image config carrying "--gdb").
func elfuseArgv(rootfs string, spec *runSpec) []string {
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
	argv = append(argv, "--")
	argv = append(argv, spec.Args...)
	return argv
}

// execElfuse replaces this process with elfuse (syscall.Exec). Used for the
// plain-rootfs path, which owns no mount to tear down: elfuse-oci
// becomes elfuse in place, so the invoking shell reaps the same pid and
// terminal signals such as Ctrl-C go straight to elfuse rather than through a
// Go middleman.
func execElfuse(rootfs string, spec *runSpec) error {
	bin, err := elfuseBin()
	if err != nil {
		return err
	}
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("elfuse binary not found at %s (set $ELFUSE_BIN): %w", bin, err)
	}
	if err := syscall.Exec(bin, elfuseArgv(rootfs, spec), os.Environ()); err != nil {
		return fmt.Errorf("exec %s: %w", bin, err)
	}
	return nil // unreachable
}

// spawnElfuseWait runs elfuse as a child and waits for it, returning the exit
// status the way a shell would (exit code, or 128+signal for signal death).
// Unlike execElfuse, elfuse-oci stays alive to reap the child, letting the
// case-sensitive path tear down its mount and COW clone after elfuse exits.
//
// The child shares this process's process group, so terminal signals (Ctrl-C)
// reach it directly; we additionally forward any such signal we receive to the
// child so a signal targeted at elfuse-oci alone still propagates, and we
// survive to reap and report the child's status rather than dying first.
func spawnElfuseWait(rootfs string, spec *runSpec) (int, error) {
	bin, err := elfuseBin()
	if err != nil {
		return 0, err
	}
	if _, err := os.Stat(bin); err != nil {
		return 0, fmt.Errorf("elfuse binary not found at %s (set $ELFUSE_BIN): %w", bin, err)
	}
	// exec.Command uses `bin` as argv[0], so drop the leading "elfuse"
	// program-name that elfuseArgv includes for syscall.Exec's sake; otherwise
	// elfuse would see "elfuse" as its first positional and try to boot a
	// guest path named "elfuse".
	cmd := exec.Command(bin, elfuseArgv(rootfs, spec)[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Intercept before Start so no window exists where a signal takes the
	// default action and kills this wrapper between launching the child and
	// entering the forward/reap loop; the channel buffers until then. SIGHUP
	// is included so a terminal hangup also flows through the forward/reap
	// path and the caller's mount/clone teardown still runs.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT,
		syscall.SIGHUP)
	defer signal.Stop(sigCh)

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("spawn %s: %w", bin, err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for {
		select {
		case err := <-done:
			state := cmd.ProcessState
			if state == nil {
				return 0, err
			}
			if ws, ok := state.Sys().(syscall.WaitStatus); ok {
				if ws.Signaled() {
					return 128 + int(ws.Signal()), nil
				}
				return ws.ExitStatus(), nil
			}
			return state.ExitCode(), nil
		case sig := <-sigCh:
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}
}
