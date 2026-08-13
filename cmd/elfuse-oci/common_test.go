// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"
	"time"
)

// TestParsePlatform pins the os/arch[/variant] shape --platform accepts and
// that String round-trips it.
func TestParsePlatform(t *testing.T) {
	cases := []struct {
		in      string
		want    Platform
		wantErr bool
	}{
		{"linux/arm64", Platform{OS: "linux", Arch: "arm64"}, false},
		{"linux/amd64/v8", Platform{OS: "linux", Arch: "amd64", Variant: "v8"}, false},
		{"darwin/arm64", Platform{}, true},
		{"windows/amd64", Platform{}, true},
		{"linux", Platform{}, true},
		{"", Platform{}, true},
		{"linux//", Platform{}, true},
		{"/arm64", Platform{}, true},
		{"linux//v8", Platform{}, true},
		{"linux/arm64/", Platform{}, true},
		{"linux/arm64/v8/extra", Platform{}, true},
		{"//", Platform{}, true},
	}
	for _, c := range cases {
		got, err := parsePlatform(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parsePlatform(%q): err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parsePlatform(%q): got %+v, want %+v", c.in, got, c.want)
		}
		if got.String() != c.in {
			t.Errorf("Platform(%q).String() = %q, want %q", c.in, got.String(), c.in)
		}
	}
}

// TestParsePullArgs pins that --store, --platform, --timeout, and the ref
// positional all land in the parsed result.
func TestParsePullArgs(t *testing.T) {
	cf, timeout, ref, err := parsePullArgs([]string{
		"--store", "/s", "--platform", "linux/amd64", "--timeout", "30s", "alpine:3"})
	if err != nil {
		t.Fatal(err)
	}
	if ref != "alpine:3" {
		t.Fatalf("ref = %q, want alpine:3", ref)
	}
	if cf.store != "/s" {
		t.Errorf("store = %q, want /s", cf.store)
	}
	if !reflect.DeepEqual(cf.platform, Platform{OS: "linux", Arch: "amd64"}) {
		t.Errorf("platform = %+v, want linux/amd64", cf.platform)
	}
	if timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", timeout)
	}
}

// TestParseInspectArgs pins that --json and --platform reach the caller.
func TestParseInspectArgs(t *testing.T) {
	cf, asJSON, ref, err := parseInspectArgs([]string{"--json", "--platform", "linux/amd64", "alpine:3"})
	if err != nil {
		t.Fatal(err)
	}
	if !asJSON {
		t.Error("asJSON = false, want true")
	}
	if ref != "alpine:3" {
		t.Errorf("ref = %q, want alpine:3", ref)
	}
	if !reflect.DeepEqual(cf.platform, Platform{OS: "linux", Arch: "amd64"}) {
		t.Errorf("platform = %+v, want linux/amd64", cf.platform)
	}
}

// TestParseCommandFlagErrors pins that malformed --platform and --timeout,
// unknown flags, and a missing ref all fail the parse.
func TestParseCommandFlagErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"malformed platform", func() error { _, _, _, err := parsePullArgs([]string{"--platform", "bogus", "alpine:3"}); return err }()},
		{"malformed timeout", func() error { _, _, _, err := parsePullArgs([]string{"--timeout", "bogus", "alpine:3"}); return err }()},
		{"unknown flag", func() error { _, _, _, err := parsePullArgs([]string{"--unknown", "alpine:3"}); return err }()},
		{"missing ref", func() error { _, _, _, err := parsePullArgs(nil); return err }()},
	}
	for _, tc := range cases {
		if tc.err == nil {
			t.Errorf("%s: got nil error", tc.name)
		}
	}
}
