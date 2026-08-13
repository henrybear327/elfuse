// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1"
)

// version is stamped at build time via -ldflags "-X main.version=...". The
// default "dev" is what `go build` without the stamp produces.
var version = "dev"

// Platform is an OCI platform triple. Variant is optional (e.g. "v8" for
// arm64); empty means "the default variant for this arch".
type Platform struct {
	OS      string
	Arch    string
	Variant string
}

func (p Platform) String() string {
	if p.Variant != "" {
		return p.OS + "/" + p.Arch + "/" + p.Variant
	}
	return p.OS + "/" + p.Arch
}

// Set implements flag.Value for --platform.
func (p *Platform) Set(s string) error {
	parsed, err := parsePlatform(s)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// defaultPlatform is linux/arm64: elfuse runs aarch64-linux guests natively via
// HVF, and x86_64 guests via Rosetta. elfuse-oci targets arm64 by default;
// --platform selects another (e.g. linux/amd64 for an x86_64 image run under
// Rosetta).
var defaultPlatform = Platform{OS: "linux", Arch: "arm64"}

// formatCreated renders a config's creation time in the CLI's fixed
// second-precision UTC form.
func formatCreated(cfg *v1.ConfigFile) string {
	return cfg.Created.UTC().Format("2006-01-02T15:04:05Z")
}

// parsePlatform parses "os/arch" or "os/arch/variant". The value must have
// exactly two or three slash-separated components, each non-empty: "linux//",
// "/arm64", "linux/arm64/", and "linux/arm64/v8/extra" are all rejected rather
// than riding through to the registry client as a nonsense platform. The OS
// must be linux: elfuse runs Linux guests, so a store entry for any other OS
// could never be consumed, and rejecting it here beats a confusing failure
// at unpack or run. Arch stays open (Rosetta hosts amd64 guests).
func parsePlatform(s string) (Platform, error) {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || len(parts) > 3 || slices.Contains(parts, "") {
		return Platform{}, fmt.Errorf("invalid --platform %q (want os/arch[/variant])", s)
	}
	if parts[0] != "linux" {
		return Platform{}, fmt.Errorf("invalid --platform %q: elfuse runs Linux guests, so the OS must be linux", s)
	}
	if len(parts) == 3 {
		return Platform{OS: parts[0], Arch: parts[1], Variant: parts[2]}, nil
	}
	return Platform{OS: parts[0], Arch: parts[1]}, nil
}

// defaultStore returns the OCI store directory: $ELFUSE_OCI_STORE if set,
// otherwise ~/.local/share/elfuse/oci. The store is an OCI image-layout
// (blobs/, index.json) plus a ref->digest pin table (see store.go).
func defaultStore() (string, error) {
	if s := os.Getenv("ELFUSE_OCI_STORE"); s != "" {
		return s, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("no --store given and $HOME unset: %w", err)
	}
	return filepath.Join(home, ".local", "share", "elfuse", "oci"), nil
}

// commonFlags holds the flags shared by every subcommand.
type commonFlags struct {
	store    string
	platform Platform
}

func (cf *commonFlags) resolveStore() error {
	if cf.store == "" {
		s, err := defaultStore()
		if err != nil {
			return err
		}
		cf.store = s
	}
	return os.MkdirAll(cf.store, 0o755)
}

// openResolvedStore is every subcommand's store preamble: resolve the store
// path (defaulting and creating it) and open the layout.
func (cf *commonFlags) openResolvedStore() (*store, error) {
	if err := cf.resolveStore(); err != nil {
		return nil, err
	}
	return openStore(cf.store)
}

// newCommandFlagSet creates a FlagSet whose parse errors are returned (not
// exited on) so main reports them uniformly, while `<cmd> -h` and a bad flag
// still print that subcommand's own flag list. The FlagSet's own error line is
// discarded (main prints the returned error); the Usage closure writes the flag
// list straight to stderr so it survives regardless.
func newCommandFlagSet(name string, cf *commonFlags) *flag.FlagSet {
	*cf = commonFlags{platform: defaultPlatform}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: elfuse-oci %s [flags]\n", name)
		fs.SetOutput(os.Stderr)
		fs.PrintDefaults()
		fs.SetOutput(io.Discard)
	}
	fs.StringVar(&cf.store, "store", "", "OCI store directory (default $ELFUSE_OCI_STORE or ~/.local/share/elfuse/oci)")
	return fs
}

// parseCommand is the shared subcommand parse step: build the FlagSet
// against a fresh commonFlags, parse args, and hand back the positional
// tail for the command's own positional-arg validation. extra carries the
// builder's parsed-value target(s), e.g. inspect's --json pointer;
// commands without extra flags use the struct{} shape.
func parseCommand[T any](build func(*commonFlags) (*flag.FlagSet, T),
	args []string) (commonFlags, T, []string, error) {
	var cf commonFlags
	fs, extra := build(&cf)
	err := fs.Parse(args)
	return cf, extra, fs.Args(), err
}

// addPlatformFlag registers --platform on the commands that resolve a
// ref to a platform-specific image (pull, inspect; the pin table is keyed
// by ref and platform). A subcommand that resolves no platform must not
// accept it: a successful parse that discards the flag reads as target
// selection that never happened.
func addPlatformFlag(fs *flag.FlagSet, cf *commonFlags) {
	fs.Var(&cf.platform, "platform", "target platform os/arch[/variant]")
}

func oneArg(cmd string, args []string, what string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("%s: expected one %s, got %d", cmd, what, len(args))
	}
	return args[0], nil
}

// parseRefCommand is parseCommand plus the single-<ref> positional every
// image-addressed subcommand takes, so the per-command wrappers cannot
// drift on the error shape.
func parseRefCommand[T any](name string,
	build func(*commonFlags) (*flag.FlagSet, T),
	args []string) (commonFlags, T, string, error) {
	cf, extra, rest, err := parseCommand(build, args)
	if err != nil {
		return cf, extra, "", err
	}
	ref, err := oneArg(name, rest, "<ref>")
	return cf, extra, ref, err
}
