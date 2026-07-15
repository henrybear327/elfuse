// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"strings"
	"testing"
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
