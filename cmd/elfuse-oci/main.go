// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

// elfuse-oci is the OCI image CLI for elfuse.
//
// It owns the OCI image pipeline (pull, store, inspect, unpack, and run
// orchestration) using go-containerregistry. For `run` it execs the existing
// `elfuse --sysroot <rootfs> <entrypoint> <args>` positional launch path,
// reusing elfuse's HVF bring-up / shebang / dynamic-linker plumbing rather
// than reinventing guest launch. elfuse itself stays a pure Linux
// syscall-to-Darwin runtime with no OCI awareness.
//
// Usage:
//
//	elfuse-oci pull   [--store DIR] [--platform os/arch[/variant]] <ref>
//	elfuse-oci unpack [--store DIR] [--rootfs DIR] <ref>
//	elfuse-oci inspect [--store DIR] [--json] <ref>
//	elfuse-oci run     [--store DIR] [--entrypoint E] [--env K=V]...
//	                         [--user UID[:GID]] [--workdir DIR] [--platform ...]
//	                         <ref> [args...]
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
  run      Pull + unpack + exec the image's entrypoint under elfuse
  help     Show this help
  version  Print the elfuse-oci version

common flags:
  --store DIR        OCI store directory (default $ELFUSE_OCI_STORE or
                     ~/.local/share/elfuse/oci)
  --platform os/arch[/variant]   Target platform (default linux/arm64)

run flags:
  --entrypoint PATH  Override the image Entrypoint (drops image Cmd)
  --env KEY=VAL      Set a guest env var (repeatable; bare KEY inherits
                     from the host environ)
  --clear-env        Start the guest env empty (only --env apply)
  --user UID[:GID]   Run as UID (and GID; defaults to UID). Symbolic names
                     are resolved against the image /etc/passwd and
                     /etc/group before exec.
  --workdir DIR      Guest-absolute initial working directory
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
	case "run":
		return cmdRun(rest)
	default:
		usage()
		return fmt.Errorf("unknown command: %s", cmd)
	}
}
