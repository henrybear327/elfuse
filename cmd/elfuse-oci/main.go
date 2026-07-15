// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

// elfuse-oci is the OCI image CLI for elfuse.
//
// It owns the OCI image pipeline (pull, store, inspect, and unpack for
// now) using go-containerregistry. elfuse itself stays a pure Linux
// syscall-to-Darwin runtime with no OCI awareness.
//
// Usage:
//
//	elfuse-oci pull   [--store DIR] [--platform os/arch[/variant]] <ref>
//	elfuse-oci unpack [--store DIR] [--rootfs DIR] <ref>
//	elfuse-oci inspect [--store DIR] [--json] <ref>
//
// <ref> is an OCI image reference (docker.io/library/alpine:3, ghcr.io/...,
// localhost:5000/foo:tag, or name@sha256:...). The default store is
// $ELFUSE_OCI_STORE or ~/.local/share/elfuse/oci.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "elfuse-oci: %s\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: elfuse-oci <command> [flags] <ref> [args...]

commands:
  pull     Pull an image reference into the local OCI store
  unpack   Unpack a stored image's layers into a rootfs directory
  inspect  Print a stored image's manifest + config
  help     Show this help
  version  Print the elfuse-oci version

common flags:
  --store DIR        OCI store directory (default $ELFUSE_OCI_STORE or
                     ~/.local/share/elfuse/oci)
  --platform os/arch[/variant]   Target platform (default linux/arm64)
`)
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	cmd, rest := args[0], args[1:]
	// A `<cmd> -h`/`--help` makes the subcommand FlagSet print its own flag list
	// and return flag.ErrHelp; treat that as success rather than an error.
	if err := dispatch(cmd, rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	return nil
}

func dispatch(cmd string, rest []string) error {
	switch cmd {
	case "help", "-h", "--help":
		usage()
		return nil
	case "version", "-V", "--version":
		fmt.Println("elfuse-oci " + version)
		return nil
	case "pull":
		return cmdPull(rest)
	case "unpack":
		return cmdUnpack(rest)
	case "inspect":
		return cmdInspect(rest)
	default:
		usage()
		return fmt.Errorf("unknown command: %s", cmd)
	}
}
