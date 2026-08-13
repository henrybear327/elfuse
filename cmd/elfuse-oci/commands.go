// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"os"
	"time"
)

// cmdPull implements `elfuse-oci pull [--store] [--platform] [--timeout] <ref>`.
func cmdPull(args []string) error {
	cf, timeout, ref, err := parsePullArgs(args)
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return pullImage(ctx, cf, s, ref)
}

// pullFlagSet's extra is the --timeout target: a bound on the whole pull,
// registry transfer included, since a hung registry has no other limit.
// 0 keeps the pull unbounded, the default because any fixed bound would
// fail large images on slow links.
func pullFlagSet(cf *commonFlags) (*flag.FlagSet, *time.Duration) {
	fs := newCommandFlagSet("pull", cf)
	addPlatformFlag(fs, cf)
	timeout := fs.Duration("timeout", 0, "fail the pull after this duration (0 = no limit)")
	return fs, timeout
}

func parsePullArgs(args []string) (commonFlags, time.Duration, string, error) {
	cf, timeout, ref, err := parseRefCommand("pull", pullFlagSet, args)
	if err != nil {
		return cf, 0, "", err
	}
	return cf, *timeout, ref, err
}

// cmdInspect implements `elfuse-oci inspect [--store] [--platform] [--json] <ref>`.
func cmdInspect(args []string) error {
	cf, asJSON, ref, err := parseInspectArgs(args)
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	return inspect(os.Stdout, s, ref, cf.platform, asJSON)
}

// inspectFlagSet registers inspect's flags once for both parsing and
// usage(); the returned pointer receives --json after Parse.
func inspectFlagSet(cf *commonFlags) (*flag.FlagSet, *bool) {
	fs := newCommandFlagSet("inspect", cf)
	addPlatformFlag(fs, cf)
	asJSON := fs.Bool("json", false, "print the raw config JSON instead of a summary")
	return fs, asJSON
}

func parseInspectArgs(args []string) (commonFlags, bool, string, error) {
	cf, asJSON, ref, err := parseRefCommand("inspect", inspectFlagSet, args)
	if err != nil {
		return cf, false, "", err
	}
	return cf, *asJSON, ref, err
}
