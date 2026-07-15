// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
)

var isMountPointFn = isMountPoint

// csMount is a case-sensitive APFS sparsebundle attached at a mount point.
// It mirrors the C sysroot_create_mount machinery in src/core/sysroot.c so
// the guest rootfs is case-sensitive (the host volume is not), fixing
// the case-collision limitation of a plain-directory rootfs.
type csMount struct {
	mountPath string     // where the volume is attached
	owned     bool       // we attached (or share) it; tear down on Close
	bundleDir string     // bundle directory holding the lock files; "" = no locking (unit tests)
	runLock   *flockFile // shared liveness lock held for this run's lifetime
}

// defaultSparseSize is the sparsebundle's virtual size. APFS sparsebundles are
// sparse, so this is a ceiling, not preallocation; 16g matches the C side and
// comfortably covers base images (the actual disk use is the unpacked size).
const defaultSparseSize = "16g"

// provisionCaseSensitive creates (if absent) and attaches a case-sensitive
// APFS sparsebundle. The unpacked base tree lives at <mountPath>/rootfs and
// persists in the sparsebundle image file across attach/detach cycles, so warm
// re-runs skip the unpack. The caller must Close the returned mount (which
// detaches it when this is the last live run) when done.
//
// Locking (see bundlelock.go): the whole provision runs under an exclusive
// attach.lock, and the returned mount holds run.lock shared until Close, so
// this run is visible to prune/rmi sweeps from BEFORE the volume is
// attached: there is no window in which the mount exists but no liveness
// marker does. An attached leftover mount is detached only after winning the
// run.lock exclusive probe, which proves no live run is executing out of it;
// when the probe reports busy the mount belongs to live runs of the same
// digest and is shared instead of ripped out from under them.
func provisionCaseSensitive(bundleDir, mountPath, size string) (*csMount, error) {
	if size == "" {
		size = defaultSparseSize
	}
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		return nil, err
	}
	image := filepath.Join(bundleDir, "rootfs.sparsebundle")

	attachLock, err := acquireAttachLock(bundleDir)
	if err != nil {
		return nil, err
	}
	defer attachLock.Close()

	// Probe run.lock. Winning it exclusively proves zero live runs: any
	// attached mount is stale (crash, kill, --keep) and safe to detach; hold
	// the lock and downgrade to shared once provisioned (safe under
	// attach.lock, see Downgrade). Losing the probe proves live runs exist:
	// take it shared (which cannot block, since exclusive takers must hold
	// attach.lock) and never detach.
	staleDetachOK := false
	runLock, err := acquireFlock(runLockPath(bundleDir), syscall.LOCK_EX|syscall.LOCK_NB)
	switch {
	case err == nil:
		staleDetachOK = true
	case errors.Is(err, errCacheBusy):
		runLock, err = acquireFlock(runLockPath(bundleDir), syscall.LOCK_SH)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	fail := func(err error) (*csMount, error) {
		runLock.Close()
		return nil, err
	}

	if _, err := os.Stat(image); os.IsNotExist(err) {
		out, err := exec.Command("hdiutil", "create",
			"-fs", "Case-sensitive APFS",
			"-size", size,
			"-type", "SPARSEBUNDLE",
			"-volname", "elfuse_sysroot",
			image).CombinedOutput()
		if err != nil {
			return fail(fmt.Errorf("hdiutil create %s: %w: %s", image, err, out))
		}
	} else if err != nil {
		return fail(err)
	}

	// Reject a symlinked mount path before any mount-status probe or detach:
	// isMountPoint/detachForce follow the link (os.Stat) and could force-detach
	// an unrelated volume. clearDir has the same guard, but only runs after the
	// detach below.
	if li, err := os.Lstat(mountPath); err == nil && li.Mode()&os.ModeSymlink != 0 {
		return fail(fmt.Errorf("mount path %s is a symlink; refusing to detach/clear", mountPath))
	}

	if isMountPointFn(mountPath) {
		if !staleDetachOK {
			// Live runs of this digest own the attach; share it.
			return &csMount{mountPath: mountPath, owned: true, bundleDir: bundleDir, runLock: runLock}, nil
		}
		// A prior run left the volume attached (crash, kill, --keep) and the
		// won run.lock probe proves nothing is executing out of it: detach so
		// we own a clean attach.
		if err := detachForce(mountPath); err != nil {
			return fail(fmt.Errorf("detach stale %s: %w", mountPath, err))
		}
	}
	// Ensure the mount point is an empty directory so hdiutil will mount onto
	// it.
	if err := clearDir(mountPath); err != nil {
		return fail(err)
	}

	// Keep stdout (the plist) separate from stderr: the failure message must
	// carry hdiutil's diagnostic, which Output() alone would discard, while
	// CombinedOutput() would corrupt the plist parse.
	attach := exec.Command("hdiutil", "attach",
		"-mountpoint", mountPath, "-plist", image)
	var attachStderr bytes.Buffer
	attach.Stderr = &attachStderr
	out, err := attach.Output()
	if err != nil {
		return fail(fmt.Errorf("hdiutil attach %s: %w: %s%s", image, err, out,
			attachStderr.Bytes()))
	}
	actual, err := parseMountpoint(string(out))
	if err != nil {
		err = fmt.Errorf("parse attach plist for %s: %w", image, err)
		return fail(detachAfterAttachError(mountPath, err))
	}

	if err := writeSpotlightMarker(actual); err != nil {
		err = fmt.Errorf("spotlight marker: %w", err)
		return fail(detachAfterAttachError(actual, err))
	}
	if staleDetachOK {
		if err := runLock.Downgrade(); err != nil {
			return fail(detachAfterAttachError(actual, err))
		}
	}
	return &csMount{mountPath: actual, owned: true, bundleDir: bundleDir, runLock: runLock}, nil
}

// rootfsDir is the base unpacked tree inside the volume.
func (m *csMount) rootfsDir() string { return filepath.Join(m.mountPath, "rootfs") }

// Close releases this run's liveness lock and detaches the volume when this
// was the last live run of the digest (last-one-out): with concurrent runs
// sharing one attach, an unconditional detach here would rip the rootfs out
// from under the survivors. A csMount without a bundleDir (unit tests,
// hand-built mounts) has no locks to consult and detaches unconditionally.
func (m *csMount) Close() error {
	if !m.owned {
		return nil
	}
	if m.bundleDir == "" {
		if err := detachForce(m.mountPath); err != nil {
			return err
		}
		m.owned = false
		return nil
	}
	// Take attach.lock BEFORE releasing our shared run.lock: it fences out a
	// concurrent sweep, which could otherwise win both locks between our
	// release and our probe and remove the bundle we are about to detach. If
	// the lifecycle lock is busy (another provision or a sweep), its holder
	// owns the mount's fate; just drop our liveness and go.
	attachLock, err := acquireFlock(attachLockPath(m.bundleDir), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		m.runLock.Close()
		m.runLock = nil
		m.owned = false
		if errors.Is(err, errCacheBusy) {
			return nil
		}
		return err
	}
	defer attachLock.Close()
	if err := m.runLock.Close(); err != nil {
		m.owned = false
		return err
	}
	m.runLock = nil
	m.owned = false
	runLock, err := acquireFlock(runLockPath(m.bundleDir), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		if errors.Is(err, errCacheBusy) {
			// Other live runs share the attach; leave the volume to them.
			return nil
		}
		return err
	}
	defer runLock.Close()
	return detachForce(m.mountPath)
}

func detachAfterAttachError(mountPath string, cause error) error {
	if err := detachForce(mountPath); err != nil {
		return errors.Join(cause, fmt.Errorf("detach %s: %w", mountPath, err))
	}
	return cause
}

var detachForce = func(mountPath string) error {
	out, err := exec.Command("hdiutil", "detach", "-force", mountPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("hdiutil detach %s: %w: %s", mountPath, err, out)
	}
	return nil
}

// writeSpotlightMarker drops .metadata_never_index so Spotlight does not index
// the (potentially large) rootfs volume.
func writeSpotlightMarker(mountPath string) error {
	return touchFile(filepath.Join(mountPath, ".metadata_never_index"))
}

// touchFile creates (or truncates) an empty marker file. The markers carry
// no content; only their existence matters.
func touchFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

// isMountPoint reports whether path is currently a mount point by comparing its
// device id against its parent's.
func isMountPoint(path string) bool {
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		return false
	}
	dev, ok := devOf(path)
	if !ok {
		return false
	}
	parent, ok := devOf(filepath.Dir(path))
	if !ok {
		return false
	}
	return dev != parent
}

func devOf(path string) (int64, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, false
	}
	return int64(st.Dev), true
}

// clearDir removes all children of dir (creating it if absent) without removing
// dir itself, so hdiutil can mount onto it. A symlink at dir is rejected:
// ReadDir/RemoveAll would follow it and empty the link's target instead of the
// mount point, so a corrupt or tampered store must fail here rather than
// delete files elsewhere.
func clearDir(dir string) error {
	if li, err := os.Lstat(dir); err == nil {
		if li.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("mount point %s is a symlink; refusing to clear it", dir)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

var mountpointRe = regexp.MustCompile(`<key>mount-point</key>\s*<string>([^<]+)</string>`)

// parseMountpoint extracts the mount-point from an hdiutil attach -plist output
// (mirroring the C parse_attach_mountpoint string scan). The scan reads raw
// XML text content, so entity references must be decoded: a store path
// containing "&" or "'" is otherwise returned in its escaped form and every
// later use (markers, rootfs, detach) targets a nonexistent path.
// html.UnescapeString covers the XML predefined entities plus numeric
// references.
func parseMountpoint(plist string) (string, error) {
	m := mountpointRe.FindStringSubmatch(plist)
	if m == nil {
		return "", fmt.Errorf("mount-point key not found in plist")
	}
	return html.UnescapeString(m[1]), nil
}
