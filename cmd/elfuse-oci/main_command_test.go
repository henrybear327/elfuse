// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1"
)

func TestRunDispatchHelpVersionAndErrors(t *testing.T) {
	stdout, stderr, err := captureOutput(t, func() error { return run([]string{"help"}) })
	if err != nil {
		t.Fatalf("run help: %v", err)
	}
	if stdout != "" {
		t.Fatalf("help stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "usage: elfuse-oci") || !strings.Contains(stderr, "commands:") {
		t.Fatalf("help stderr missing usage:\n%s", stderr)
	}

	stdout, stderr, err = captureOutput(t, func() error { return run([]string{"--version"}) })
	if err != nil {
		t.Fatalf("run --version: %v", err)
	}
	if strings.TrimSpace(stdout) != "elfuse-oci "+version {
		t.Fatalf("version stdout = %q, want elfuse-oci %s", stdout, version)
	}
	if stderr != "" {
		t.Fatalf("version stderr = %q, want empty", stderr)
	}

	_, stderr, err = captureOutput(t, func() error { return run(nil) })
	if err == nil || !strings.Contains(err.Error(), "no command") {
		t.Fatalf("run nil err = %v, want no command", err)
	}
	if !strings.Contains(stderr, "usage: elfuse-oci") {
		t.Fatalf("no-arg stderr missing usage:\n%s", stderr)
	}

	_, stderr, err = captureOutput(t, func() error { return run([]string{"bogus"}) })
	if err == nil || !strings.Contains(err.Error(), "unknown command: bogus") {
		t.Fatalf("run bogus err = %v, want unknown command", err)
	}
	if !strings.Contains(stderr, "usage: elfuse-oci") {
		t.Fatalf("unknown-command stderr missing usage:\n%s", stderr)
	}
}

func TestMainSubprocessExitBehavior(t *testing.T) {
	stdout, stderr, err := runMainSubprocess(t, "version")
	if err != nil {
		t.Fatalf("main version err = %v, stdout=%q stderr=%q", err, stdout, stderr)
	}
	if strings.TrimSpace(stdout) != "elfuse-oci "+version {
		t.Fatalf("main version stdout = %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("main version stderr = %q, want empty", stderr)
	}

	stdout, stderr, err = runMainSubprocess(t, "bogus")
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 {
		t.Fatalf("main bogus err = %T %v, want exit 1", err, err)
	}
	if stdout != "" {
		t.Fatalf("main bogus stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "elfuse-oci: unknown command: bogus") {
		t.Fatalf("main bogus stderr = %q, want formatted error", stderr)
	}

	_, stderr, err = runMainSubprocess(t)
	exit, ok = err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 {
		t.Fatalf("main no-arg err = %T %v, want exit 1", err, err)
	}
	if !strings.Contains(stderr, "elfuse-oci: no command given") {
		t.Fatalf("main no-arg stderr = %q, want formatted error", stderr)
	}
}

func TestRunDispatchesAllSubcommands(t *testing.T) {
	root := t.TempDir()
	img := tinyImage(t)
	withFakeCranePull(t, func(ref string, opts ...crane.Option) (v1.Image, error) {
		if ref != "local:tiny" {
			t.Fatalf("pull ref = %q, want local:tiny", ref)
		}
		return img, nil
	})

	stdout, stderr, err := captureOutput(t, func() error {
		return run([]string{"pull", "--store", root, "local:tiny"})
	})
	if err != nil || !strings.Contains(stderr, "Pulled local:tiny") {
		t.Fatalf("run pull stderr=%q err=%v, want pull summary", stderr, err)
	}

	for _, cmd := range []string{"list", "images"} {
		stdout, _, err = captureOutput(t, func() error {
			return run([]string{cmd, "--store", root})
		})
		if err != nil || !strings.Contains(stdout, "local:tiny") {
			t.Fatalf("run %s stdout=%q err=%v, want list row", cmd, stdout, err)
		}
	}

	stdout, _, err = captureOutput(t, func() error {
		return run([]string{"inspect", "--store", root, "local:tiny"})
	})
	if err != nil || !strings.Contains(stdout, "Ref:         local:tiny") {
		t.Fatalf("run inspect stdout=%q err=%v, want inspect output", stdout, err)
	}

	unpackRoot := filepath.Join(t.TempDir(), "unpack-rootfs")
	_, stderr, err = captureOutput(t, func() error {
		return run([]string{"unpack", "--store", root, "--rootfs", unpackRoot, "local:tiny"})
	})
	if err != nil || !strings.Contains(stderr, "Unpacked local:tiny") {
		t.Fatalf("run unpack stderr=%q err=%v, want unpack summary", stderr, err)
	}

	withFakeExecElfuse(t, func(rootfs string, spec *runSpec, _ *flockFile) error { return nil })
	runRoot := filepath.Join(t.TempDir(), "run-rootfs")
	_, _, err = captureOutput(t, func() error {
		return run([]string{"run", "--store", root, "--plain-rootfs", "--rootfs", runRoot, "local:tiny"})
	})
	if err != nil {
		t.Fatalf("run run --plain-rootfs: %v", err)
	}

	_, stderr, err = captureOutput(t, func() error {
		return run([]string{"prune", "--store", root, "--dry-run"})
	})
	if err != nil || !strings.Contains(stderr, "Would reclaim") {
		t.Fatalf("run prune stderr=%q err=%v, want dry-run summary", stderr, err)
	}

	_, stderr, err = captureOutput(t, func() error {
		return run([]string{"rmi", "--store", root, "local:tiny"})
	})
	if err != nil || !strings.Contains(stderr, "Removed local:tiny") {
		t.Fatalf("run rmi stderr=%q err=%v, want rmi summary", stderr, err)
	}
}
