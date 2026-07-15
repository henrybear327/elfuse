// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"
)

func TestParsePlatform(t *testing.T) {
	cases := []struct {
		in      string
		want    Platform
		wantErr bool
	}{
		{"linux/arm64", Platform{OS: "linux", Arch: "arm64"}, false},
		{"linux/amd64/v8", Platform{OS: "linux", Arch: "amd64", Variant: "v8"}, false},
		{"darwin/arm64", Platform{OS: "darwin", Arch: "arm64"}, false},
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

func TestParsePullArgs(t *testing.T) {
	cf, ref, err := parsePullArgs([]string{"--store", "/s", "--platform", "linux/amd64", "alpine:3"})
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
}

func TestParseUnpackArgs(t *testing.T) {
	cf, rootfs, ref, err := parseUnpackArgs([]string{"--rootfs=/tmp/rootfs", "alpine:3"})
	if err != nil {
		t.Fatal(err)
	}
	if cf.platform != defaultPlatform {
		t.Errorf("platform = %+v, want default %+v", cf.platform, defaultPlatform)
	}
	if rootfs != "/tmp/rootfs" {
		t.Errorf("rootfs = %q, want /tmp/rootfs", rootfs)
	}
	if ref != "alpine:3" {
		t.Errorf("ref = %q, want alpine:3", ref)
	}
}

func TestParseInspectArgs(t *testing.T) {
	_, asJSON, ref, err := parseInspectArgs([]string{"--json", "alpine:3"})
	if err != nil {
		t.Fatal(err)
	}
	if !asJSON {
		t.Error("asJSON = false, want true")
	}
	if ref != "alpine:3" {
		t.Errorf("ref = %q, want alpine:3", ref)
	}
}

func TestParseRunArgs(t *testing.T) {
	cf, rf, ref, tail, err := parseRunArgs([]string{
		"--store", "/s",
		"--entrypoint", "/bin/sh",
		"--env", "A=1",
		"--env=B=2",
		"--clear-env",
		"--user", "1000:1000",
		"--workdir", "/work",
		"--rootfs", "/tmp/rootfs",
		"--plain-rootfs",
		"--sparse-size", "32g",
		"--no-clone",
		"--keep",
		"alpine:3",
		"-c", "echo hi",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cf.store != "/s" {
		t.Errorf("store = %q, want /s", cf.store)
	}
	if ref != "alpine:3" {
		t.Errorf("ref = %q, want alpine:3", ref)
	}
	if !reflect.DeepEqual(tail, []string{"-c", "echo hi"}) {
		t.Errorf("tail = %v, want [-c echo hi]", tail)
	}
	if rf.entrypoint != "/bin/sh" || rf.user != "1000:1000" || rf.workdir != "/work" || rf.rootfs != "/tmp/rootfs" {
		t.Errorf("run flags = %+v", rf)
	}
	if !rf.plainRootfs || rf.sparseSize != "32g" || !rf.noClone || !rf.keepRootfs {
		t.Errorf("sparse run flags = %+v", rf)
	}
	if !rf.clearEnv {
		t.Error("clearEnv = false, want true")
	}
	if !reflect.DeepEqual(rf.env, []string{"A=1", "B=2"}) {
		t.Errorf("env = %v, want [A=1 B=2]", rf.env)
	}
}

func TestParseCommandFlagErrors(t *testing.T) {
	cases := []struct {
		name string
		fn   func() error
	}{
		{"malformed platform", func() error { _, _, err := parsePullArgs([]string{"--platform", "bogus", "alpine:3"}); return err }},
		{"unknown flag", func() error { _, _, err := parsePullArgs([]string{"--unknown", "alpine:3"}); return err }},
		{"missing flag value", func() error { _, _, _, err := parseUnpackArgs([]string{"--rootfs"}); return err }},
		{"run missing ref", func() error { _, _, _, _, err := parseRunArgs([]string{"--env", "A=1"}); return err }},
		{"list extra arg", func() error { _, _, err := parseListArgs([]string{"alpine:3"}); return err }},
		{"rmi missing ref", func() error { _, _, _, err := parseRmiArgs([]string{"--force"}); return err }},
		{"prune all without cache", func() error { _, _, err := parsePruneArgs([]string{"--all"}); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Errorf("%s: got nil error, want parse failure", tc.name)
			}
		})
	}
}

func TestParseLifecycleArgs(t *testing.T) {
	cf, asJSON, err := parseListArgs([]string{"--store", "/s", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if cf.store != "/s" || !asJSON {
		t.Fatalf("list parse = store %q json %v, want /s true", cf.store, asJSON)
	}

	cf, force, ref, err := parseRmiArgs([]string{"--force", "alpine:3"})
	if err != nil {
		t.Fatal(err)
	}
	if force != true || ref != "alpine:3" || cf.platform != defaultPlatform {
		t.Fatalf("rmi parse = force %v ref %q platform %+v", force, ref, cf.platform)
	}

	cf, opts, err := parsePruneArgs([]string{"--cache", "--all", "--dry-run"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.cache || !opts.all || !opts.dryRun || cf.platform != defaultPlatform {
		t.Fatalf("prune parse = opts %+v platform %+v", opts, cf.platform)
	}
}
