// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
)

// inspect prints a stored image's manifest + config. With --json the raw config
// JSON is emitted (one object); otherwise a human-readable summary.
func inspect(w io.Writer, s *store, ref string, asJSON bool) error {
	img, err := s.image(ref)
	if err != nil {
		return err
	}
	d, err := img.Digest()
	if err != nil {
		return err
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return err
	}
	cf := cfg.Config

	if asJSON {
		// The raw config blob, not a re-marshal of the parsed struct: fields
		// ggcr does not model (vendor extensions) must survive, and the bytes
		// should diff cleanly against `skopeo inspect --config`.
		b, err := img.RawConfigFile()
		if err != nil {
			return err
		}
		// A failed write (closed pipe, full disk on a redirect) must not
		// exit 0: callers would consume truncated JSON as success.
		if _, err := fmt.Fprintf(w, "%s\n", b); err != nil {
			return fmt.Errorf("inspect: write: %w", err)
		}
		return nil
	}

	// bufio latches the first write error and reports it at Flush, so the
	// summary can print unconditionally without an if around every line.
	bw := bufio.NewWriter(w)
	w = bw

	fmt.Fprintf(w, "%-12s %s\n", "Ref:", ref)
	fmt.Fprintf(w, "%-12s %s\n", "Digest:", d)
	fmt.Fprintf(w, "%-12s %s/%s\n", "Platform:", cfg.OS, cfg.Architecture)
	if !cfg.Created.IsZero() {
		fmt.Fprintf(w, "%-12s %s\n", "Created:", cfg.Created.UTC().Format("2006-01-02T15:04:05Z"))
	}
	fmt.Fprintf(w, "%-12s %v\n", "Entrypoint:", cf.Entrypoint)
	fmt.Fprintf(w, "%-12s %v\n", "Cmd:", cf.Cmd)
	fmt.Fprintf(w, "%-12s %s\n", "WorkingDir:", cf.WorkingDir)
	fmt.Fprintf(w, "%-12s %s\n", "User:", cf.User)
	fmt.Fprintf(w, "Env (%d):\n", len(cf.Env))
	for _, e := range cf.Env {
		fmt.Fprintf(w, "  %s\n", e)
	}
	layers, err := img.Layers()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Layers (%d):\n", len(layers))
	for i, l := range layers {
		ld, err := l.Digest()
		if err != nil {
			return fmt.Errorf("inspect: layer %d digest: %w", i, err)
		}
		ls, err := l.Size()
		if err != nil {
			return fmt.Errorf("inspect: layer %d size: %w", i, err)
		}
		fmt.Fprintf(w, "  %2d  %s  %d bytes\n", i, ld, ls)
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("inspect: write: %w", err)
	}
	return nil
}
