// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestUsageOnStderrAndErrors(t *testing.T) {
	var err error
	stdout, stderr := captureOutput(t, func() { err = run(nil) })
	if err == nil || err.Error() != "no command given" {
		t.Fatalf("run(nil) err = %v", err)
	}
	if stdout != "" {
		t.Fatalf("usage must go to stderr, stdout = %q", stdout)
	}
	mustContain(t, stderr, "usage: elfuse-oci", "pull", "inspect", "help", "version")

	stdout, _ = captureOutput(t, func() { err = run([]string{"bogus"}) })
	if err == nil || !strings.Contains(err.Error(), "unknown command: bogus") {
		t.Fatalf("unknown command err = %v", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestVersionOnStdout(t *testing.T) {
	var err error
	stdout, stderr := captureOutput(t, func() { err = run([]string{"version"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout, "elfuse-oci ") || stderr != "" {
		t.Fatalf("version stdout = %q stderr = %q", stdout, stderr)
	}
}

func TestSubcommandHelpIsSuccess(t *testing.T) {
	var err error
	_, stderr := captureOutput(t, func() { err = run([]string{"pull", "-h"}) })
	if err != nil {
		t.Fatalf("pull -h must succeed, got %v", err)
	}
	mustContain(t, stderr, "usage: elfuse-oci pull", "-platform", "-store", "-timeout")
}

func TestBadFlagIsError(t *testing.T) {
	var err error
	_, stderr := captureOutput(t, func() { err = run([]string{"inspect", "--nope", "x"}) })
	if err == nil {
		t.Fatal("bad flag must error")
	}
	mustContain(t, stderr, "usage: elfuse-oci inspect")
}

// Each command's own positional validation, which only its handler
// produces, proves dispatch per entry: an empty arg list for the
// ref-taking commands, a stray positional for clean.
func TestEveryCommandReachesItsHandler(t *testing.T) {
	for _, c := range commands {
		var args []string
		if c.name == "clean" {
			args = []string{"stray"}
		}
		var err error
		captureOutput(t, func() { err = dispatch(c.name, args) })
		if err == nil || !strings.Contains(err.Error(), c.name+":") {
			t.Errorf("%s: want its own arg error, got %v", c.name, err)
		}
	}
}
