// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"howett.net/plist"
)

// csAvailable gates the sparsebundle strategy at the build-tag seam, so
// cmdRun asks the strategy rather than the OS.
const csAvailable = true

// Test seams: hdiutil needs a real volume, and the spawn a real binary.
var (
	spawnForRun    = spawnElfuseWait
	isMountPointFn = isMountPoint
)

const defaultSparseSize = "16g"

// runCaseSensitive is the darwin default: a per-digest case-sensitive
// sparsebundle (a case-folding directory cannot hold case-colliding image
// names), unpacked once and run out of a per-run COW clone. The mount
// stays attached so the next run is warm; clean owns the detach.
func runCaseSensitive(ctx context.Context, rc *runContext) (err error) {
	bundleDir, err := rc.s.cacheDir(cacheCS, rc.digest)
	if err != nil {
		return err
	}
	// Under the store lock: a second cold run of this digest would
	// otherwise clear the mount path between this run's probe and attach,
	// and clean could detach a volume mid-provision.
	var mount string
	if err := rc.s.withLock(ctx, func() error {
		var err error
		mount, err = provisionCaseSensitive(bundleDir, rc.rf.cs.sparseSize)
		return err
	}); err != nil {
		return err
	}
	base := csBaseTree(mount)
	if err := ensureRootfs(ctx, rc.s, rc.ref, rc.m, base, false); err != nil {
		return err
	}

	sysroot := base
	if !rc.rf.cs.noClone {
		sysroot = filepath.Join(mount, fmt.Sprintf("run-%d-%d", os.Getpid(), time.Now().UnixNano()))
		if err := unix.Clonefile(base, sysroot, unix.CLONE_NOFOLLOW); err != nil {
			return fmt.Errorf("clone rootfs for run: %w", err)
		}
		// One teardown for every exit. --keep preserves the clone on a
		// failed launch too, since inspecting a broken preparation is
		// what --keep is for; a removal failure never masks a nonzero
		// guest exit.
		defer func() {
			if rc.rf.cs.keepRootfs {
				fmt.Fprintf(os.Stderr, "kept clone: %s\nmount stays attached: %s\n", sysroot, mount)
				return
			}
			if rmErr := os.RemoveAll(sysroot); rmErr != nil {
				if err == nil || err == exitStatus(0) {
					err = fmt.Errorf("remove run clone: %w", rmErr)
				} else {
					fmt.Fprintf(os.Stderr, "elfuse-oci: cleanup after %v: %v\n", err, rmErr)
				}
			}
		}()
	}

	spec, err := computeRunSpec(rc.cfg, rc.rf, sysroot, rc.tail)
	if err != nil {
		return err
	}
	if err := prepareRootfsForRun(sysroot, spec); err != nil {
		return err
	}
	code, err := spawnForRun(rc.bin, sysroot, spec)
	if err != nil {
		return err
	}
	return exitStatus(code)
}

// provisionCaseSensitive creates the sparsebundle image if absent and
// attaches it at the slot's mount path unless already mounted. An attach
// that lands anywhere else is detached and refused, so the warm probe,
// clean, and the run clone all read the one path.
func provisionCaseSensitive(bundleDir, size string) (string, error) {
	mountPath := csMountPath(bundleDir)
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		return "", err
	}
	if err := ensureBundleImage(csBundleImage(bundleDir), size); err != nil {
		return "", err
	}
	// A symlink at the mount path would aim the probe, the clear, and any
	// later detach at an unrelated directory.
	if err := rejectSymlink(mountPath, "attach over it"); err != nil {
		return "", err
	}
	if isMountPointFn(mountPath) {
		// A mount there is reused only when it is this slot's own bundle:
		// anything else would be written into as the base tree and
		// force-detached by clean.
		if err := requireOwnBundle(bundleDir, mountPath); err != nil {
			return "", err
		}
		return mountPath, nil
	}
	if err := clearDir(mountPath); err != nil {
		return "", err
	}
	// -nobrowse keeps the volume out of Finder, where an eject would pull
	// the rootfs from under a running guest.
	out, err := hdiutil("attach", "-nobrowse", "-mountpoint", mountPath, "-plist", csBundleImage(bundleDir))
	if err != nil {
		return "", err
	}
	// attach has already mounted the volume, so a failure past this point
	// detaches, or the slot leaks a live mount.
	actual, err := parseMountpoint(out)
	if err != nil {
		return "", detachAfter(err, mountPath)
	}
	if !samePath(actual, mountPath) {
		return "", detachAfter(fmt.Errorf("hdiutil attach mounted at %s, want %s", actual, mountPath), actual)
	}
	if err := writeSpotlightMarker(mountPath); err != nil {
		return "", detachAfter(err, mountPath)
	}
	return mountPath, nil
}

// samePath compares two existing paths with symlinks resolved: hdiutil
// reports paths canonical, /private/var for a /var spelling.
func samePath(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

// requireOwnBundle errors unless hdiutil reports the slot's bundle
// attached at mountPath.
func requireOwnBundle(bundleDir, mountPath string) error {
	out, err := hdiutil("info", "-plist")
	if err != nil {
		return err
	}
	image := csBundleImage(bundleDir)
	mounts, err := parseAttachedBundles(out, func(p string) bool { return samePath(p, image) })
	if err != nil {
		return err
	}
	for _, m := range mounts {
		if samePath(m.mount, mountPath) {
			return nil
		}
	}
	return fmt.Errorf("%s is mounted but not from %s; detach it or clean --cache", mountPath, image)
}

// detachAfter detaches the volume a failed provision left mounted; a
// detach that fails too is reported beside err, since the slot then
// leaks a live mount.
func detachAfter(err error, mountPath string) error {
	if dErr := detachForce(mountPath); dErr != nil {
		return fmt.Errorf("%w; %v", err, dErr)
	}
	return err
}

func ensureBundleImage(image, size string) error {
	if size == "" {
		size = defaultSparseSize
	}
	// The size is a ceiling (sparsebundles are sparse), so it is inert
	// against an existing bundle; say so when it differs from the default.
	// A symlink here would make attach mount whatever it points at.
	if fi, err := os.Lstat(image); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("sparsebundle %s is a symlink, refusing to use it", image)
		}
		if size != defaultSparseSize {
			fmt.Fprintf(os.Stderr, "elfuse-oci: sparsebundle exists; --sparse-size ignored (clean --cache to recreate)\n")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	_, err := hdiutil("create",
		"-fs", "Case-sensitive APFS",
		"-size", size,
		"-type", "SPARSEBUNDLE",
		"-volname", "elfuse_sysroot",
		image)
	if err != nil {
		// A partial bundle left behind would pass the Lstat above on every
		// later run, with only clean --cache as the way out.
		if rmErr := os.RemoveAll(image); rmErr != nil {
			return fmt.Errorf("%w; %v", err, rmErr)
		}
		return err
	}
	return nil
}

// hdiutil runs one hdiutil command and returns its stdout; stderr is
// kept apart so a failure carries the diagnostic without corrupting a
// plist answer.
func hdiutil(args ...string) ([]byte, error) {
	out, err := exec.Command("hdiutil", args...).Output()
	if err != nil {
		var stderr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = ee.Stderr
		}
		return nil, fmt.Errorf("hdiutil %s: %w: %s", strings.Join(args, " "), err, stderr)
	}
	return out, nil
}

func detachForce(mountPath string) error {
	_, err := hdiutil("detach", mountPath, "-force")
	return err
}

// writeSpotlightMarker keeps Spotlight off the rootfs volume.
func writeSpotlightMarker(mountPath string) error {
	f, err := os.OpenFile(filepath.Join(mountPath, ".metadata_never_index"), os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

// isMountPoint compares path's st_dev against its parent's, so a
// same-device mount would read as absent.
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

// clearDir empties dir (creating it if absent) without removing it, so
// hdiutil can mount onto it.
func clearDir(dir string) error {
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

// hdiutil's plist answers, the keys this code reads.
type hdiutilEntity struct {
	MountPoint string `plist:"mount-point"`
}

type hdiutilImage struct {
	ImagePath string          `plist:"image-path"`
	Entities  []hdiutilEntity `plist:"system-entities"`
}

// parseMountpoint returns the mount-point of hdiutil attach -plist, whose
// answer is one image dict; the entity carrying a mount-point is the volume.
func parseMountpoint(out []byte) (string, error) {
	var img hdiutilImage
	if _, err := plist.Unmarshal(out, &img); err != nil {
		return "", fmt.Errorf("hdiutil attach: %w", err)
	}
	for _, e := range img.Entities {
		if e.MountPoint != "" {
			return e.MountPoint, nil
		}
	}
	return "", fmt.Errorf("mount-point key not found in plist")
}

// bundleMount is one attached store bundle as hdiutil info reports it.
type bundleMount struct {
	image string // the rootfs.sparsebundle path
	mount string // where its volume is mounted
}

// parseAttachedBundles reads hdiutil info -plist, whose top level is a
// dict with an images array, and keeps the images keep accepts.
func parseAttachedBundles(out []byte, keep func(image string) bool) ([]bundleMount, error) {
	var info struct {
		Images []hdiutilImage `plist:"images"`
	}
	if _, err := plist.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("hdiutil info: %w", err)
	}
	var mounts []bundleMount
	for _, img := range info.Images {
		if !keep(img.ImagePath) {
			continue
		}
		for _, e := range img.Entities {
			if e.MountPoint != "" {
				mounts = append(mounts, bundleMount{image: img.ImagePath, mount: e.MountPoint})
			}
		}
	}
	return mounts, nil
}

// detachStoreBundles force-detaches every mounted bundle volume under the
// store's cs/ tree, so clean can remove the bundles.
func detachStoreBundles(s *store) error {
	base := s.cacheBase(cacheCS)
	entries, err := os.ReadDir(base)
	// Nothing is mounted under an absent or non-directory base, and clean
	// is the recovery path for a malformed store.
	if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
		return nil
	} else if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		mnt := csMountPath(filepath.Join(base, e.Name()))
		if err := rejectSymlink(mnt, "detach it"); err != nil {
			return err
		}
		if !isMountPointFn(mnt) {
			continue
		}
		if err := detachForce(mnt); err != nil {
			return err
		}
	}
	return nil
}

// isStoreBundlePath recognizes <store>/cs/sha256/<hex>/rootfs.sparsebundle.
func isStoreBundlePath(p string) bool {
	slot := filepath.Dir(p)
	if p != csBundleImage(slot) {
		return false
	}
	if _, err := digestHex("sha256:" + filepath.Base(slot)); err != nil {
		return false
	}
	algo := filepath.Dir(slot)
	return filepath.Base(algo) == "sha256" && filepath.Base(filepath.Dir(algo)) == cacheCS
}

// detachOrphanBundles force-detaches every attached store bundle whose
// image is gone: a store removed under a live mount (a killed test's
// TempDir, an rm -rf) leaves the volume attached with no store to clean
// it through. Bundles whose store exists belong to that store's clean.
func detachOrphanBundles() (int, error) {
	out, err := hdiutil("info", "-plist")
	if err != nil {
		return 0, err
	}
	bundles, err := parseAttachedBundles(out, isStoreBundlePath)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range bundles {
		if _, err := os.Lstat(b.image); !os.IsNotExist(err) {
			continue
		}
		if err := detachForce(b.mount); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
