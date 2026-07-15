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

// parsePlatform parses "os/arch" or "os/arch/variant". The value must have
// exactly two or three slash-separated components, each non-empty: "linux//",
// "/arm64", "linux/arm64/", and "linux/arm64/v8/extra" are all rejected rather
// than riding through to the registry client as a nonsense platform.
func parsePlatform(s string) (Platform, error) {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || len(parts) > 3 || slices.Contains(parts, "") {
		return Platform{}, fmt.Errorf("invalid --platform %q (want os/arch[/variant])", s)
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
	// platformSet records an explicit --platform: run uses it to validate the
	// pinned image, while the default platform stays advisory so a ref pulled
	// for another platform still runs without re-specifying --platform.
	platformSet bool
}

// platformFlag adapts commonFlags.platform to flag.Value while recording
// that the flag was set explicitly.
type platformFlag struct{ cf *commonFlags }

func (pf platformFlag) String() string {
	if pf.cf == nil {
		return ""
	}
	return pf.cf.platform.String()
}

func (pf platformFlag) Set(s string) error {
	if err := pf.cf.platform.Set(s); err != nil {
		return err
	}
	pf.cf.platformSet = true
	return nil
}

// resolveStore fills cf.store with the default when unset and ensures the
// directory exists.
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
	fs.Var(platformFlag{cf}, "platform", "target platform os/arch[/variant]")
	return fs
}

type repeatedStringFlag []string

func (f *repeatedStringFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *repeatedStringFlag) Set(s string) error {
	*f = append(*f, s)
	return nil
}

func oneArg(cmd string, args []string, what string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("%s: expected one %s, got %d", cmd, what, len(args))
	}
	return args[0], nil
}

func noArgs(cmd string, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("%s: takes no <ref> argument", cmd)
	}
	return nil
}
