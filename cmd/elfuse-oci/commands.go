// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

// The subcommands share common-flag parsing (common.go) and the OCI
// image-layout store (store.go). pull/unpack/inspect are pure store ops.

// cmdPull implements `elfuse-oci pull [--store] [--platform] <ref>`.
func cmdPull(args []string) error {
	cf, ref, err := parsePullArgs(args)
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	return pullImage(cf, s, ref)
}

func parsePullArgs(args []string) (commonFlags, string, error) {
	var cf commonFlags
	fs := newCommandFlagSet("pull", &cf)
	if err := fs.Parse(args); err != nil {
		return cf, "", err
	}
	ref, err := oneArg("pull", fs.Args(), "<ref>")
	return cf, ref, err
}

// cmdUnpack implements `elfuse-oci unpack [--store] [--rootfs DIR] <ref>`.
func cmdUnpack(args []string) error {
	cf, rootfs, ref, err := parseUnpackArgs(args)
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	digest, err := s.digestFor(ref)
	if err != nil {
		return err
	}
	if rootfs == "" {
		rootfs, err = defaultRootfsForDigest(cf.store, digest)
		if err != nil {
			return err
		}
	}
	fmt.Printf("Unpacking %s -> %s\n", ref, rootfs)
	if err := unpackImage(s, ref, rootfs); err != nil {
		return err
	}
	fmt.Printf("Unpacked %s\n", ref)
	return nil
}

func parseUnpackArgs(args []string) (commonFlags, string, string, error) {
	var cf commonFlags
	var rootfs string
	fs := newCommandFlagSet("unpack", &cf)
	fs.StringVar(&rootfs, "rootfs", "", "")
	if err := fs.Parse(args); err != nil {
		return cf, "", "", err
	}
	ref, err := oneArg("unpack", fs.Args(), "<ref>")
	return cf, rootfs, ref, err
}

// cmdInspect implements `elfuse-oci inspect [--store] [--json] <ref>`.
func cmdInspect(args []string) error {
	cf, asJSON, ref, err := parseInspectArgs(args)
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	return inspect(os.Stdout, s, ref, asJSON)
}

func parseInspectArgs(args []string) (commonFlags, bool, string, error) {
	var cf commonFlags
	var asJSON bool
	fs := newCommandFlagSet("inspect", &cf)
	fs.BoolVar(&asJSON, "json", false, "")
	if err := fs.Parse(args); err != nil {
		return cf, false, "", err
	}
	ref, err := oneArg("inspect", fs.Args(), "<ref>")
	return cf, asJSON, ref, err
}
