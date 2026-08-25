// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var execElfuseForRun = execElfuse

// pullForRun is cmdRun's auto-pull, swappable so tests stay offline.
var pullForRun = pullImage

// exitStatus is the guest's exit status, carried out of a spawn-and-wait
// run as an error so every teardown on the way out still runs; main
// exits with it.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("guest exited %d", int(e)) }

// runContext is one resolved run invocation: the store, the pinned
// image, the parsed flags, the guest argv tail, and the elfuse binary.
type runContext struct {
	s      *store
	ref    string
	digest string
	m      ocispec.Manifest
	cfg    ocispec.Image
	rf     runFlags
	tail   []string
	bin    string
}

// cmdRun implements elfuse-oci run [flags] <ref> [args...]. Flags parse
// only up to the first positional; everything after <ref> passes verbatim
// as the guest argv tail (Docker's run IMAGE ARGS convention).
func cmdRun(args []string) error {
	cf, rf, rest, err := parseCommand(runFlagSet, args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("run: expected <ref> [args...]")
	}
	ref, tail := rest[0], rest[1:]
	// csAvailable is the build-tag seam (csrootfs_darwin.go and its stub).
	useCS := csAvailable && rf.rootfs == "" && !rf.plainRootfs
	// Everything decidable from the flags and the host is refused before
	// any network work: a typo must not cost a multi-hundred-MB pull.
	if err := validateRunFlags(*rf); err != nil {
		return err
	}
	if err := refuseCSFlags(rf.cs, useCS); err != nil {
		return err
	}
	bin, err := resolveElfuseBin()
	if err != nil {
		return err
	}
	s, err := cf.openResolvedStore()
	if err != nil {
		return err
	}
	if err := refuseRootfsInStore("run", s.root, rf.rootfs); err != nil {
		return err
	}
	ctx := context.Background()
	digest, err := s.digestFor(ref, cf.platform)
	if errors.Is(err, errNotPulled) {
		// Auto-pull only the simply-missing case: a corrupt store must
		// surface, not hide behind a network pull.
		digest, err = pullForRun(ctx, cf, s, ref)
	}
	if err != nil {
		return err
	}
	m, err := s.manifestFor(ctx, digest)
	if err != nil {
		return err
	}
	_, cfg, err := s.configFor(ctx, m)
	if err != nil {
		return err
	}
	rc := &runContext{s: s, ref: ref, digest: digest, m: m, cfg: cfg, rf: *rf, tail: tail, bin: bin}
	if useCS {
		return runCaseSensitive(ctx, rc)
	}
	return runPlainRootfs(ctx, rc)
}

func runFlagSet(cf *commonFlags) (*flag.FlagSet, *runFlags) {
	fs := newCommandFlagSet("run", cf)
	addPlatformFlag(fs, cf)
	rf := &runFlags{}
	fs.Func("entrypoint", "override the image Entrypoint (drops image Cmd); \"\" clears it, as docker does", func(v string) error {
		rf.entrypoint, rf.entrypointSet = v, true
		return nil
	})
	fs.Var(repeatedString{&rf.env}, "env", "set a guest env var KEY=VAL (repeatable; bare KEY inherits from the host environ)")
	fs.BoolVar(&rf.clearEnv, "clear-env", false, "start the guest env empty (only --env apply)")
	fs.StringVar(&rf.user, "user", "", "run as UID[:GID]; symbolic names resolve against the image /etc/passwd and /etc/group")
	fs.StringVar(&rf.workdir, "workdir", "", "guest-absolute initial working directory")
	fs.StringVar(&rf.rootfs, "rootfs", "", "use an explicit rootfs directory (plain dir)")
	fs.BoolVar(&rf.plainRootfs, "plain-rootfs", false, "use a plain directory rootfs instead of the macOS sparsebundle")
	fs.StringVar(&rf.cs.sparseSize, "sparse-size", "", "sparsebundle virtual size (default 16g; sparsebundle path, macOS)")
	fs.BoolVar(&rf.cs.noClone, "no-clone", false, "run against the base tree without a per-run COW clone (sparsebundle path, macOS)")
	fs.BoolVar(&rf.cs.keepRootfs, "keep", false, "keep the per-run COW clone and mount for inspection (sparsebundle path, macOS)")
	return fs, rf
}

// refuseCSFlags rejects a sparsebundle-only flag on a path that cannot
// honor it, and --keep without a clone to keep, before any network work;
// parse-and-ignore misleads.
func refuseCSFlags(c csFlags, useCS bool) error {
	if name := c.set(); name != "" && !useCS {
		if csAvailable {
			return fmt.Errorf("run: --%s needs the sparsebundle path; drop --plain-rootfs/--rootfs", name)
		}
		return fmt.Errorf("run: --%s needs the sparsebundle path, which requires macOS", name)
	}
	if c.keepRootfs && c.noClone {
		return fmt.Errorf("run: --keep needs a clone; drop --no-clone")
	}
	return nil
}

// repeatedString collects every occurrence of a repeatable string flag.
type repeatedString struct {
	dst *[]string
}

func (r repeatedString) String() string { return "" }
func (r repeatedString) Set(s string) error {
	*r.dst = append(*r.dst, s)
	return nil
}

// runPlainRootfs materializes a plain directory rootfs (the store's
// digest-keyed cache, or an explicit --rootfs, unpacked only when absent)
// and execs elfuse against it. The unpack precedes computeRunSpec because
// resolveUser reads the rootfs /etc files.
func runPlainRootfs(ctx context.Context, rc *runContext) error {
	rootfs := rc.rf.rootfs
	if rootfs == "" {
		dest, err := rc.s.cacheDir(cacheRootfs, rc.digest)
		if err != nil {
			return err
		}
		if err := ensureRootfs(ctx, rc.s, rc.ref, rc.m, dest, false); err != nil {
			return err
		}
		rootfs = dest
	} else if exists, err := existingDirectory("run", rootfs); err != nil {
		return err
	} else if !exists {
		fmt.Fprintf(os.Stderr, "Unpacking %s -> %s\n", rc.ref, rootfs)
		if err := unpackImageFresh(ctx, rc.s, rc.m, rootfs); err != nil {
			return err
		}
	}
	spec, err := computeRunSpec(rc.cfg, rc.rf, rootfs, rc.tail)
	if err != nil {
		return err
	}
	if err := prepareRootfsForRun(rootfs, spec); err != nil {
		return err
	}
	return execElfuseForRun(rc.bin, rootfs, spec)
}

// resolveElfuseBin is $ELFUSE_BIN (an override hook for tests and
// wrapper scripts), else the sibling of this executable
// (build/elfuse-oci -> build/elfuse), and must exist.
func resolveElfuseBin() (string, error) {
	bin := os.Getenv("ELFUSE_BIN")
	if bin == "" {
		exe, err := os.Executable()
		if err == nil {
			// os.Executable keeps the invoked spelling, so a symlinked
			// launcher would look beside the link rather than the binary.
			exe, err = filepath.EvalSymlinks(exe)
		}
		if err != nil {
			return "", fmt.Errorf("locate elfuse: %w", err)
		}
		bin = filepath.Join(filepath.Dir(exe), "elfuse")
	}
	if _, err := os.Stat(bin); err != nil {
		return "", fmt.Errorf("elfuse binary not found at %s (set $ELFUSE_BIN): %w", bin, err)
	}
	return bin, nil
}

// elfuseArgv builds elfuse --sysroot <rootfs> ... -- <entrypoint> <args>.
// --clear-env plus --env entries hand the guest exactly spec.Env, and "--"
// keeps an image Entrypoint beginning with "-" out of elfuse's flags.
func elfuseArgv(rootfs string, spec *runSpec) []string {
	argv := []string{
		"elfuse",
		"--sysroot", rootfs,
		"--user", fmt.Sprintf("%d:%d", spec.UID, spec.GID),
		"--workdir", spec.Workdir,
		"--clear-env",
	}
	for _, e := range spec.Env {
		argv = append(argv, "--env", e)
	}
	argv = append(argv, "--")
	argv = append(argv, spec.Args...)
	return argv
}

// spawnElfuseWait runs elfuse as a child and returns its exit status the
// way a shell would (exit code, or 128+signal), forwarding signals
// delivered to this wrapper; the caller stays alive to tear down.
func spawnElfuseWait(bin, rootfs string, spec *runSpec) (int, error) {
	// exec.Command supplies bin as argv[0] itself.
	cmd := exec.Command(bin, elfuseArgv(rootfs, spec)[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Intercepted before Start, so no window exists where a signal kills
	// this wrapper between launching the child and the forward loop;
	// SIGHUP included so a terminal hangup still tears the clone down.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT,
		syscall.SIGHUP)
	defer signal.Stop(sigCh)

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("spawn %s: %w", bin, err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for {
		select {
		case err := <-done:
			state := cmd.ProcessState
			if state == nil {
				return 0, err
			}
			ws := state.Sys().(syscall.WaitStatus)
			if ws.Signaled() {
				return 128 + int(ws.Signal()), nil
			}
			return ws.ExitStatus(), nil
		case sig := <-sigCh:
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}
}

// execElfuse replaces this process with elfuse: the plain-rootfs path
// owns no mount to tear down, so the invoking shell reaps the same pid
// and Ctrl-C reaches elfuse directly.
func execElfuse(bin, rootfs string, spec *runSpec) error {
	err := syscall.Exec(bin, elfuseArgv(rootfs, spec), os.Environ())
	return fmt.Errorf("exec %s: %w", bin, err)
}
