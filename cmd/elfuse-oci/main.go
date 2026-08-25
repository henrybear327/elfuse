// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

// elfuse-oci is the OCI image CLI for elfuse. It pulls images into a local
// content store and materializes them as sysroots for elfuse, so elfuse
// itself stays a Linux syscall-to-Darwin runtime with no OCI awareness.
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

// command wires one subcommand into dispatch and usage. flags rebuilds the
// subcommand's FlagSet without parsing, so usage() prints the registered
// flags themselves and cannot drift from what parsing accepts.
type command struct {
	name    string
	args    string
	summary string
	run     func([]string) error
	flags   func(*commonFlags) *flag.FlagSet
}

// flagsOnly adapts a FlagSet builder that also returns its parsed-value
// target(s) to the usage-only shape command.flags wants.
func flagsOnly[T any](build func(*commonFlags) (*flag.FlagSet, T)) func(*commonFlags) *flag.FlagSet {
	return func(cf *commonFlags) *flag.FlagSet {
		fs, _ := build(cf)
		return fs
	}
}

var commands = []command{
	{"pull", "<ref>", "Pull an image reference into the local OCI store",
		cmdPull, flagsOnly(pullFlagSet)},
	{"unpack", "<ref>", "Unpack a stored image's layers into a rootfs directory",
		cmdUnpack, flagsOnly(unpackFlagSet)},
	{"inspect", "<ref>", "Print a stored image's manifest + config",
		cmdInspect, flagsOnly(inspectFlagSet)},
}

func usage() {
	fmt.Fprint(os.Stderr, "usage: elfuse-oci <command> [flags] [args...]\n\ncommands:\n")
	for _, c := range commands {
		fmt.Fprintf(os.Stderr, "  %-8s %-6s %s\n", c.name, c.args, c.summary)
	}
	fmt.Fprint(os.Stderr, `  help            Show this help
  version         Print the elfuse-oci version
`)
	for _, c := range commands {
		var cf commonFlags
		fs := c.flags(&cf)
		fmt.Fprintf(os.Stderr, "\n%s flags:\n", c.name)
		fs.SetOutput(os.Stderr)
		fs.PrintDefaults()
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	// <cmd> -h makes the subcommand FlagSet print its own flag list and
	// return flag.ErrHelp; treat that as success rather than an error.
	err := dispatch(args[0], args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func dispatch(cmd string, rest []string) error {
	switch cmd {
	case "help", "-h", "--help":
		usage()
		return nil
	case "version", "-V", "--version":
		fmt.Println("elfuse-oci " + version)
		return nil
	}
	for _, c := range commands {
		if cmd == c.name {
			return c.run(rest)
		}
	}
	usage()
	return fmt.Errorf("unknown command: %s", cmd)
}
