// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

// defaultPlatform is linux/arm64: elfuse runs aarch64 guests natively
// via HVF and x86_64 guests via Rosetta (--platform linux/amd64).
var defaultPlatform = ocispec.Platform{OS: "linux", Architecture: "arm64"}

// parsePlatform is containerd's parser and normalizer, so linux/aarch64
// and linux/arm64/v8 both pin under linux/arm64, plus the rule that a
// store entry for any OS but linux or any architecture but the two
// elfuse runs could never be consumed.
func parsePlatform(s string) (ocispec.Platform, error) {
	p, err := platforms.Parse(s)
	if err != nil {
		return ocispec.Platform{}, fmt.Errorf("invalid --platform: %w", err)
	}
	if p.OS != "linux" {
		return ocispec.Platform{}, fmt.Errorf("invalid --platform %q: elfuse runs Linux guests, so the OS must be linux", s)
	}
	p = platforms.Normalize(p)
	if p.Architecture != "arm64" && p.Architecture != "amd64" {
		return ocispec.Platform{}, fmt.Errorf("invalid --platform %q: elfuse runs arm64 and amd64 guests", s)
	}
	return p, nil
}

// defaultStore is $ELFUSE_OCI_STORE, else ~/.local/share/elfuse/oci.
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
	platform ocispec.Platform
}

func (cf *commonFlags) resolveStore() error {
	if cf.store == "" {
		s, err := defaultStore()
		if err != nil {
			return err
		}
		cf.store = s
	}
	return nil
}

// openResolvedStore resolves the store path and opens (creating) the layout.
func (cf *commonFlags) openResolvedStore() (*store, error) {
	if err := cf.resolveStore(); err != nil {
		return nil, err
	}
	return openStore(cf.store)
}

// newCommandFlagSet creates a FlagSet whose parse errors are returned (not
// exited on) so main reports them uniformly, while <cmd> -h and a bad flag
// still print that subcommand's own flag list on stderr.
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

// addPlatformFlag registers --platform on the commands that resolve a ref
// to a platform-specific image; a command that resolves none must not
// accept it, or a successful parse reads as target selection.
func addPlatformFlag(fs *flag.FlagSet, cf *commonFlags) {
	fs.Var(platformFlag{cf}, "platform", "target platform os/arch[/variant]")
}

// platformFlag is the flag.Value of --platform. String tolerates a nil
// cf: flag.PrintDefaults calls it on a reflect-made zero value.
type platformFlag struct {
	cf *commonFlags
}

func (p platformFlag) String() string {
	if p.cf == nil {
		return ""
	}
	return platforms.Format(p.cf.platform)
}

func (p platformFlag) Set(s string) error {
	pl, err := parsePlatform(s)
	if err != nil {
		return err
	}
	p.cf.platform = pl
	return nil
}

// parseCommand is the shared subcommand parse step: build the FlagSet
// against a fresh commonFlags, parse args, and hand back the positional
// tail. extra carries the builder's parsed-value target(s).
func parseCommand[T any](build func(*commonFlags) (*flag.FlagSet, T),
	args []string) (commonFlags, T, []string, error) {
	var cf commonFlags
	fs, extra := build(&cf)
	err := fs.Parse(args)
	return cf, extra, fs.Args(), err
}

// parseRefCommand is parseCommand plus the single-<ref> positional every
// image-addressed subcommand takes.
func parseRefCommand[T any](name string,
	build func(*commonFlags) (*flag.FlagSet, T),
	args []string) (commonFlags, T, string, error) {
	cf, extra, rest, err := parseCommand(build, args)
	if err != nil {
		return cf, extra, "", err
	}
	if len(rest) != 1 {
		return cf, extra, "", fmt.Errorf("%s: expected one <ref>, got %d", name, len(rest))
	}
	return cf, extra, rest[0], nil
}
