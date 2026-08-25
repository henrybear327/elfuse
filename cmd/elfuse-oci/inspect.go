// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// cmdInspect implements elfuse-oci inspect [--store] [--platform] [--json] <ref>.
func cmdInspect(args []string) error {
	cf, asJSON, ref, err := parseRefCommand("inspect", inspectFlagSet, args)
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	return inspect(context.Background(), os.Stdout, s, ref, cf.platform, *asJSON)
}

func inspectFlagSet(cf *commonFlags) (*flag.FlagSet, *bool) {
	fs := newCommandFlagSet("inspect", cf)
	addPlatformFlag(fs, cf)
	asJSON := fs.Bool("json", false, "print the raw config JSON instead of a summary")
	return fs, asJSON
}

// inspect prints a summary of a stored image, or with --json its raw
// config blob verbatim.
func inspect(ctx context.Context, w io.Writer, s *store, ref string, platform ocispec.Platform, asJSON bool) error {
	d, m, err := s.loadRef(ctx, ref, platform)
	if err != nil {
		return err
	}
	raw, cfg, err := s.configFor(ctx, m)
	if err != nil {
		return err
	}

	if asJSON {
		// A failed write (closed pipe, full disk on a redirect) must not
		// exit 0: callers would consume truncated JSON as success.
		if _, err := fmt.Fprintf(w, "%s\n", raw); err != nil {
			return fmt.Errorf("inspect: write: %w", err)
		}
		return nil
	}

	// bufio latches the first write error for Flush, so the summary needs
	// no if around every line.
	bw := bufio.NewWriter(w)
	w = bw

	fmt.Fprintf(w, "%-12s %s\n", "Ref:", ref)
	fmt.Fprintf(w, "%-12s %s\n", "Digest:", d)
	fmt.Fprintf(w, "%-12s %s/%s\n", "Platform:", printable(cfg.OS), printable(cfg.Architecture))
	if cfg.Created != nil && !cfg.Created.IsZero() {
		fmt.Fprintf(w, "%-12s %s\n", "Created:", cfg.Created.UTC().Format("2006-01-02T15:04:05Z"))
	}
	fmt.Fprintf(w, "%-12s %v\n", "Entrypoint:", printableAll(cfg.Config.Entrypoint))
	fmt.Fprintf(w, "%-12s %v\n", "Cmd:", printableAll(cfg.Config.Cmd))
	fmt.Fprintf(w, "%-12s %s\n", "WorkingDir:", printable(cfg.Config.WorkingDir))
	fmt.Fprintf(w, "%-12s %s\n", "User:", printable(cfg.Config.User))
	fmt.Fprintf(w, "Env (%d):\n", len(cfg.Config.Env))
	for _, e := range cfg.Config.Env {
		fmt.Fprintf(w, "  %s\n", printable(e))
	}
	fmt.Fprintf(w, "Layers (%d):\n", len(m.Layers))
	for i, l := range m.Layers {
		fmt.Fprintf(w, "  %2d  %s  %d bytes\n", i, l.Digest, l.Size)
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("inspect: write: %w", err)
	}
	return nil
}

// printable quotes a config string that holds a non-printable rune: the
// config is the image's, and a newline or escape sequence in it would
// forge a summary line or drive the terminal.
func printable(s string) string {
	if strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) {
		return strconv.Quote(s)
	}
	return s
}

func printableAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = printable(s)
	}
	return out
}
