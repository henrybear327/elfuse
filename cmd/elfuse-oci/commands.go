// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
)

// The four subcommands share common-flag parsing (common.go) and the OCI
// image-layout store (store.go). pull/unpack/inspect are pure store ops; run
// additionally resolves the runspec and execs elfuse (run.go, csrun.go).

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
	fs.StringVar(&rootfs, "rootfs", "", "unpack into DIR (default: the store's digest-keyed rootfs cache)")
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
	fs.BoolVar(&asJSON, "json", false, "print the raw image config JSON")
	if err := fs.Parse(args); err != nil {
		return cf, false, "", err
	}
	ref, err := oneArg("inspect", fs.Args(), "<ref>")
	return cf, asJSON, ref, err
}

// cmdRun runs an image: `elfuse-oci run [flags] <ref> [args...]`.
//
// Flags are parsed only up to the first positional (the reference); everything
// after the reference is the guest argv tail and is passed verbatim (no flag
// parsing), matching Docker's `run IMAGE ARGS` convention.
func cmdRun(args []string) error {
	cf, rf, ref, tail, err := parseRunArgs(args)
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	img, err := s.image(ref)
	if err != nil {
		// Auto-pull only when the ref is simply absent, so `run` is
		// self-sufficient on first use. Any other failure (corrupt refs.json,
		// unreadable layout) must surface rather than mask itself behind a
		// fresh network pull.
		if !errors.Is(err, errNotPulled) {
			return err
		}
		if err := pullImage(cf, s, ref); err != nil {
			return err
		}
		img, err = s.image(ref)
		if err != nil {
			return err
		}
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return err
	}
	// An explicit --platform must match the pinned image: the store pins one
	// digest per ref, so a ref pulled for another platform would otherwise
	// launch silently under the wrong architecture.
	if cf.platformSet {
		got := Platform{OS: cfg.OS, Arch: cfg.Architecture, Variant: cfg.Variant}
		want := cf.platform
		if got.OS != want.OS || got.Arch != want.Arch ||
			(want.Variant != "" && got.Variant != want.Variant) {
			return fmt.Errorf(
				"run: %s is pinned for %s, not %s; `pull --platform %s %s` (after rmi) to switch",
				ref, got, want, want, ref)
		}
	}
	digest, err := img.Digest()
	if err != nil {
		return err
	}
	digestStr := digest.String()

	// Choose the rootfs path. Default: a case-sensitive APFS sparsebundle so
	// the guest's case-sensitive filenames don't collide on the host's
	// case-insensitive volume, with a per-run COW clone for isolation and
	// warm-run speed. --plain-rootfs (or an explicit --rootfs) opts out to the
	// plain-directory path (syscall.Exec, no mount lifecycle).
	useCS := rf.rootfs == "" && !rf.plainRootfs

	if useCS {
		return runCaseSensitive(cf, s, ref, digestStr, cfg, rf, tail)
	}

	// Plain-directory path.
	if rf.rootfs == "" {
		rf.rootfs, err = defaultRootfsForDigest(cf.store, digestStr)
		if err != nil {
			return err
		}
	}
	// Ensure the rootfs is unpacked before computing the spec, because
	// resolveUser reads <rootfs>/etc/passwd and /etc/group. Re-unpack only if
	// absent; a stale rootfs is the user's concern (run `unpack` to refresh).
	if _, err := os.Stat(rf.rootfs); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		fmt.Fprintf(os.Stderr, "Unpacking %s -> %s\n", ref, rf.rootfs)
		if err := unpackImage(s, ref, rf.rootfs); err != nil {
			return err
		}
	}
	spec, err := computeRunSpec(cfg, rf, rf.rootfs, tail)
	if err != nil {
		return err
	}
	// Inject host-truth /etc/{resolv.conf,hosts,hostname} into the rootfs so
	// the guest's resolver/hostname work. On the plain path this mutates the
	// unpacked rootfs directory (acceptable: --plain-rootfs is the v1/debug
	// path; re-runs overwrite the same small files).
	if err := injectRuntimeFiles(rf.rootfs); err != nil {
		return err
	}
	return execElfuseForRun(rf.rootfs, spec)
}

func parseRunArgs(args []string) (commonFlags, runFlags, string, []string, error) {
	var cf commonFlags
	var rf runFlags
	var env repeatedStringFlag
	fs := newCommandFlagSet("run", &cf)
	fs.StringVar(&rf.entrypoint, "entrypoint", "", "override the image Entrypoint (drops the image Cmd)")
	fs.Var(&env, "env", "set a guest env var KEY=VAL (repeatable; bare KEY inherits from the host)")
	fs.BoolVar(&rf.clearEnv, "clear-env", false, "start the guest env empty (only --env applies)")
	fs.StringVar(&rf.user, "user", "", "run as UID[:GID] or name[:group] resolved via the image /etc/passwd,group")
	fs.StringVar(&rf.workdir, "workdir", "", "guest-absolute initial working directory")
	fs.StringVar(&rf.rootfs, "rootfs", "", "use an explicit rootfs directory (plain dir, no sparsebundle)")
	fs.BoolVar(&rf.plainRootfs, "plain-rootfs", false, "use a plain directory rootfs instead of the macOS sparsebundle")
	fs.StringVar(&rf.sparseSize, "sparse-size", "", "sparsebundle virtual size (default 16g; macOS only)")
	fs.BoolVar(&rf.noClone, "no-clone", false, "run against the base tree without a per-run COW clone (macOS only)")
	fs.BoolVar(&rf.keepRootfs, "keep", false, "keep the per-run COW clone and mount for inspection (macOS only)")
	if err := fs.Parse(args); err != nil {
		return cf, rf, "", nil, err
	}
	rf.env = []string(env)
	rest := fs.Args()
	if len(rest) == 0 {
		return cf, rf, "", nil, fmt.Errorf("run: expected <ref> [args...]")
	}
	return cf, rf, rest[0], rest[1:], nil
}
