// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sys/unix"
)

var (
	ensureCaseSensitiveRootfsForRun = ensureCaseSensitiveRootfs
	clonefileForRun                 = unix.Clonefile
	spawnElfuseWaitForRun           = spawnElfuseWait
	cleanupCloneAndMountForRun      = cleanupCloneAndMount
	osExitForRun                    = os.Exit
	runNowUnixNano                  = func() int64 { return time.Now().UnixNano() }
)

// keptSidecarName marks a whole sparsebundle as holding run --keep retained
// output. It lives beside the bundle's sparsebundle image and flocks, outside
// the mounted volume, so a cold rmi can detect a deliberate keep without
// attaching a detached bundle to look for .elfuse-keep clones inside it. The
// only thing that removes a kept clone is whole-bundle removal (rmi --force,
// prune --cache --all), which deletes this sidecar along with it, so the marker
// never goes stale.
const keptSidecarName = "kept"

func keptSidecarPath(bundle string) string {
	return filepath.Join(bundle, keptSidecarName)
}

// writeKeptSidecar records that m's bundle holds run --keep retained output.
// m.mountPath is <bundle>/mnt, so the sidecar lands beside the bundle image.
func writeKeptSidecar(m *csMount) error {
	return touchFile(keptSidecarPath(filepath.Dir(m.mountPath)))
}

// ensureCaseSensitiveRootfs provisions (creating if absent) and attaches a
// case-sensitive APFS sparsebundle for ref, unpacking the image's layers into
// <mount>/rootfs when that base tree is absent. It returns the attached mount
// (the caller must Close it to detach) and the rootfs path to use as --sysroot.
//
// The unpacked base tree persists in the sparsebundle image file across
// attach/detach cycles, so warm re-runs skip the (slow) unpack and pay only the
// attach.
func ensureCaseSensitiveRootfs(cf commonFlags, s *store, ref, digest, size string) (*csMount, string, error) {
	bundle, err := csBundleDirForDigest(cf.store, digest)
	if err != nil {
		return nil, "", err
	}
	mountPath := mountPointPath(bundle)
	m, err := provisionCaseSensitive(bundle, mountPath, size)
	if err != nil {
		return nil, "", err
	}
	rootfs := m.rootfsDir()
	published, err := storeRootfsPublished(rootfs)
	if err != nil {
		return nil, "", errors.Join(err, closeMount(m))
	}
	if !published {
		fmt.Fprintf(os.Stderr, "Unpacking %s -> %s\n", ref, rootfs)
		if err := unpackImage(s, ref, rootfs); err != nil {
			return nil, "", errors.Join(err, closeMount(m))
		}
	}
	return m, rootfs, nil
}

// runCaseSensitive is the default `run` path: attach the digest-keyed
// case-sensitive sparsebundle, make a per-run COW clone of the warm base tree,
// exec elfuse against the clone, then tear the clone down and detach. On the
// happy path it does not return: it os.Exits with elfuse's status. It returns
// an error on setup failure, and on a post-run cleanup failure after a guest
// exit of zero; when the guest exits nonzero, the cleanup error is only
// printed and the guest status still wins (os.Exit), so a guest failure code
// is never masked by teardown.
//
// The clone lives in the same APFS volume as the base tree (clonefile is
// intra-volume only), so it is instant and free until the guest writes (COW).
// It isolates each run's mutations from the warm base, so re-runs stay clean.
func runCaseSensitive(cf commonFlags, s *store, ref, digest string, cfg *v1.ConfigFile, rf runFlags, tail []string) error {
	m, baseRootfs, err := ensureCaseSensitiveRootfsForRun(cf, s, ref, digest, rf.sparseSize)
	if err != nil {
		return err
	}
	// NOTE: we cannot defer m.Close() because os.Exit below skips defers,
	// which would leak the attached sparsebundle. Close explicitly on every
	// exit path.

	// Per-run COW clone. --no-clone runs against the base tree directly (mutations
	// then persist into the warm tree; useful for debugging or when clonefile is
	// unavailable).
	sysroot := baseRootfs
	var cloneDir string
	if !rf.noClone {
		cloneDir = filepath.Join(m.mountPath, fmt.Sprintf("run-%d-%d", os.Getpid(), runNowUnixNano()))
		if err := os.RemoveAll(cloneDir); err != nil {
			err = fmt.Errorf("remove stale COW clone %s: %w", cloneDir, err)
			return errors.Join(err, closeMount(m))
		}
		if err := clonefileForRun(baseRootfs, cloneDir, unix.CLONE_NOFOLLOW); err != nil {
			err = fmt.Errorf("COW clone %s -> %s: %w", baseRootfs, cloneDir, err)
			return errors.Join(err, closeMount(m))
		}
		sysroot = cloneDir
	}

	// Any failure past this point must tear down the clone and the mount.
	fail := func(err error) error {
		return errors.Join(err, cleanupCloneAndMountForRun(cloneDir, rf.keepRootfs, m))
	}
	spec, err := computeRunSpec(cfg, rf, sysroot, tail)
	if err != nil {
		return fail(err)
	}
	// On the clone path sysroot is the ephemeral COW clone, so the warm base
	// tree stays clean; under --no-clone sysroot is the base tree and the
	// injected /etc files are overwritten in place (the user opted into
	// mutating the base).
	if err := prepareRootfsForRun(sysroot, spec); err != nil {
		return fail(err)
	}

	code, err := spawnElfuseWaitForRun(sysroot, spec, m.runLock)
	var cleanupErr error
	if rf.keepRootfs {
		// --keep leaves the clone and the mount in place for inspection. The
		// clone lives in the sparsebundle volume, so the mount must stay
		// attached for it to be reachable on the host; a later run reattaches
		// (detaching this stale mount first) and the kept clone reappears.
		if cloneDir != "" {
			fmt.Fprintf(os.Stderr, "kept clone: %s\n", cloneDir)
		}
		fmt.Fprintf(os.Stderr, "mount stays attached: %s\n", m.mountPath)
	} else {
		cleanupErr = cleanupCloneAndMountForRun(cloneDir, false, m)
	}
	if err != nil {
		return errors.Join(err, cleanupErr)
	}
	if cleanupErr != nil {
		if code != 0 {
			fmt.Fprintf(os.Stderr, "elfuse-oci: cleanup after exit %d: %v\n", code, cleanupErr)
			osExitForRun(code)
			return nil // unreachable
		}
		return cleanupErr
	}
	osExitForRun(code)
	return nil // unreachable
}

func cleanupCloneAndMount(cloneDir string, keep bool, m *csMount) error {
	return errors.Join(removeClone(cloneDir, keep), closeMount(m))
}

func closeMount(m *csMount) error {
	if err := m.Close(); err != nil {
		return fmt.Errorf("detach %s: %w", m.mountPath, err)
	}
	return nil
}

// removeClone deletes the ephemeral COW clone unless --keep was requested or
// there is none (the --no-clone path).
func removeClone(cloneDir string, keep bool) error {
	if cloneDir == "" || keep {
		return nil
	}
	return os.RemoveAll(cloneDir)
}
