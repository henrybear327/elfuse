// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withDarwinCacheSeams swaps the darwin mount-probe and force-detach seams
// for a test and restores them on cleanup.
func withDarwinCacheSeams(t *testing.T, isMount func(string) bool, detach func(string) error) {
	t.Helper()
	oldIsMount := isMountPointFn
	oldDetach := detachForce
	if isMount != nil {
		isMountPointFn = isMount
	}
	if detach != nil {
		detachForce = detach
	}
	t.Cleanup(func() {
		isMountPointFn = oldIsMount
		detachForce = oldDetach
	})
}

// hdiutil attach -plist output is an array of system entity dictionaries. We
// only care about the mount-point. This fixture is a trimmed-down capture of the
// real shape (system-entities -> dict -> mount-point key/string).
const attachPlistFixture = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>system-entities</key>
		<array>
			<dict>
				<key>content-hint</key>
				<string>Apple_APFS</string>
				<key>dev-entry</key>
				<string>/dev/disk3s1</string>
				<key>mount-point</key>
				<string>/Volumes/elfuse_sysroot</string>
				<key>potentially-mountable</key>
				<integer>1</integer>
			</dict>
		</array>
	</dict>
</array>
</plist>`

func TestParseMountpoint(t *testing.T) {
	got, err := parseMountpoint(attachPlistFixture)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/Volumes/elfuse_sysroot" {
		t.Errorf("got %q, want /Volumes/elfuse_sysroot", got)
	}
}

func TestParseMountpointMissing(t *testing.T) {
	if _, err := parseMountpoint("<plist><array><dict></dict></array></plist>"); err == nil {
		t.Fatal("expected error when mount-point absent")
	}
}

func TestParseMountpointWhitespaceBetweenKeyAndString(t *testing.T) {
	in := `<key>mount-point</key>
			<string>/Volumes/x</string>`
	got, err := parseMountpoint(in)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/Volumes/x" {
		t.Errorf("got %q, want /Volumes/x", got)
	}
}

func TestIsMountPointPlainDir(t *testing.T) {
	dir := t.TempDir()
	if isMountPoint(dir) {
		t.Errorf("fresh temp dir reported as mount point")
	}
}

func TestRemoveCloneRemovesDir(t *testing.T) {
	clone := filepath.Join(t.TempDir(), "run-1-1")
	if err := os.MkdirAll(clone, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := removeClone(clone, false); err != nil {
		t.Fatalf("removeClone: %v", err)
	}
	if _, err := os.Stat(clone); !os.IsNotExist(err) {
		t.Fatalf("clone after removeClone: %v, want IsNotExist", err)
	}
}

func TestRemoveCloneKeepLeavesDir(t *testing.T) {
	clone := filepath.Join(t.TempDir(), "run-1-1")
	if err := os.MkdirAll(clone, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := removeClone(clone, true); err != nil {
		t.Fatalf("removeClone keep: %v", err)
	}
	if _, err := os.Stat(clone); err != nil {
		t.Fatalf("clone after keep: %v, want present", err)
	}
}

func TestCSMountCloseReportsDetachError(t *testing.T) {
	oldDetach := detachForce
	t.Cleanup(func() { detachForce = oldDetach })
	detachForce = func(path string) error {
		return fmt.Errorf("detach failed for %s", path)
	}

	m := &csMount{mountPath: "/tmp/elfuse-test-mount", owned: true}
	err := m.Close()
	if err == nil || !strings.Contains(err.Error(), "detach failed") {
		t.Fatalf("Close err = %v, want detach failure", err)
	}
	if !m.owned {
		t.Fatal("Close cleared ownership after failed detach")
	}
}

func TestCSMount(t *testing.T) {
	t.Run("rootfsDir", func(t *testing.T) {
		m := &csMount{mountPath: "/tmp/elfuse-mounted", owned: true}
		if got := m.rootfsDir(); got != "/tmp/elfuse-mounted/rootfs" {
			t.Fatalf("rootfsDir = %q, want /tmp/elfuse-mounted/rootfs", got)
		}
	})

	t.Run("close detaches once", func(t *testing.T) {
		oldDetach := detachForce
		var detached []string
		detachForce = func(path string) error {
			detached = append(detached, path)
			return nil
		}
		t.Cleanup(func() { detachForce = oldDetach })

		m := &csMount{mountPath: "/tmp/elfuse-mounted", owned: true}
		if err := m.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if m.owned {
			t.Fatal("Close left mount owned after successful detach")
		}
		if len(detached) != 1 || detached[0] != "/tmp/elfuse-mounted" {
			t.Fatalf("detached = %v, want [/tmp/elfuse-mounted]", detached)
		}
		if err := m.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if len(detached) != 1 {
			t.Fatalf("second Close detached again: %v", detached)
		}
	})

	t.Run("detachAfterAttachError joins both errors", func(t *testing.T) {
		oldDetach := detachForce
		detachForce = func(path string) error { return errors.New("detach failed") }
		t.Cleanup(func() { detachForce = oldDetach })

		err := detachAfterAttachError("/tmp/mnt", errors.New("attach parse failed"))
		if err == nil || !strings.Contains(err.Error(), "attach parse failed") || !strings.Contains(err.Error(), "detach failed") {
			t.Fatalf("detachAfterAttachError = %v, want joined cause and detach error", err)
		}
	})
}

func TestSparsebundleFilesystemHelpers(t *testing.T) {
	dir := t.TempDir()
	if err := writeSpotlightMarker(dir); err != nil {
		t.Fatalf("writeSpotlightMarker: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".metadata_never_index")); err != nil {
		t.Fatalf("spotlight marker missing: %v", err)
	}

	childFile := filepath.Join(dir, "file")
	childDir := filepath.Join(dir, "subdir")
	if err := os.WriteFile(childFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(childDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := clearDir(dir); err != nil {
		t.Fatalf("clearDir existing: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("clearDir left entries %v, want empty dir", entries)
	}

	missing := filepath.Join(t.TempDir(), "created")
	if err := clearDir(missing); err != nil {
		t.Fatalf("clearDir missing: %v", err)
	}
	if fi, err := os.Stat(missing); err != nil || !fi.IsDir() {
		t.Fatalf("clearDir missing produced fi=%v err=%v, want dir", fi, err)
	}

	// A symlinked mount dir must be rejected, not followed: clearing through
	// it would empty the link's target directory outside the OCI cache.
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "precious"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "mnt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := clearDir(link); err == nil {
		t.Fatal("clearDir followed a symlinked mount dir, want error")
	}
	if _, err := os.Stat(filepath.Join(target, "precious")); err != nil {
		t.Fatalf("symlink target contents were removed: %v", err)
	}

	if _, ok := devOf(dir); !ok {
		t.Fatal("devOf temp dir returned ok=false")
	}
	if _, ok := devOf(filepath.Join(dir, "does-not-exist")); ok {
		t.Fatal("devOf missing path returned ok=true")
	}
}

func installFakeHdiutil(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "hdiutil")
	body := `#!/bin/sh
case "$1" in
create)
	if [ "${HDIUTIL_FAIL_CREATE:-}" = "1" ]; then
		echo "create failed"
		exit 7
	fi
	for last do :; done
	mkdir -p "$last"
	exit 0
	;;
attach)
	if [ "${HDIUTIL_FAIL_ATTACH:-}" = "1" ]; then
		echo "attach diagnostic on stderr" >&2
		exit 5
	fi
	if [ "${HDIUTIL_BAD_PLIST:-}" = "1" ]; then
		printf '<plist></plist>'
		exit 0
	fi
	printf '<key>mount-point</key><string>%s</string>' "$HDIUTIL_MOUNT"
	exit 0
	;;
detach)
	if [ -n "${HDIUTIL_DETACH_LOG:-}" ]; then
		echo "$3" >> "$HDIUTIL_DETACH_LOG"
	fi
	exit 0
	;;
*)
	echo "unexpected hdiutil command $1"
	exit 9
	;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestProvisionCaseSensitiveWithFakeHdiutilSuccess(t *testing.T) {
	installFakeHdiutil(t)
	withDarwinCacheSeams(t, func(string) bool { return false }, nil)
	bundle := filepath.Join(t.TempDir(), "bundle")
	requestedMount := filepath.Join(t.TempDir(), "requested-mount")
	actualMount := filepath.Join(t.TempDir(), "actual-mount")
	if err := os.MkdirAll(actualMount, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HDIUTIL_MOUNT", actualMount)

	m, err := provisionCaseSensitive(bundle, requestedMount, "32m")
	if err != nil {
		t.Fatalf("provisionCaseSensitive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bundle, "rootfs.sparsebundle")); err != nil {
		t.Fatalf("sparsebundle image not created: %v", err)
	}
	if m.mountPath != actualMount || !m.owned {
		t.Fatalf("mount = %+v, want actual mount and owned", m)
	}
	if _, err := os.Stat(filepath.Join(actualMount, ".metadata_never_index")); err != nil {
		t.Fatalf("spotlight marker missing: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close fake mount: %v", err)
	}
}

func TestProvisionCaseSensitiveWithFakeHdiutilFailures(t *testing.T) {
	cases := []struct {
		name string
		// setup configures the fake hdiutil for this failure mode and returns the
		// requested mount path plus the mount path the detach log must record
		// ("" to skip the detach-log check).
		setup   func(t *testing.T, detachLog string) (requestedMount, wantDetach string)
		wantErr []string
	}{
		{
			name: "create failure",
			setup: func(t *testing.T, detachLog string) (string, string) {
				t.Setenv("HDIUTIL_FAIL_CREATE", "1")
				t.Setenv("HDIUTIL_MOUNT", t.TempDir())
				return filepath.Join(t.TempDir(), "mnt"), ""
			},
			wantErr: []string{"hdiutil create", "create failed"},
		},
		{
			// hdiutil writes its diagnostics to stderr, which must reach the
			// error message: with a bare Output() the operator only sees
			// "exit status N".
			name: "attach failure surfaces hdiutil stderr",
			setup: func(t *testing.T, detachLog string) (string, string) {
				t.Setenv("HDIUTIL_FAIL_ATTACH", "1")
				t.Setenv("HDIUTIL_MOUNT", t.TempDir())
				return filepath.Join(t.TempDir(), "mnt"), ""
			},
			wantErr: []string{"hdiutil attach", "attach diagnostic on stderr"},
		},
		{
			name: "bad attach plist detaches requested mount",
			setup: func(t *testing.T, detachLog string) (string, string) {
				t.Setenv("HDIUTIL_BAD_PLIST", "1")
				t.Setenv("HDIUTIL_DETACH_LOG", detachLog)
				requestedMount := filepath.Join(t.TempDir(), "requested")
				return requestedMount, requestedMount
			},
			wantErr: []string{"parse attach plist"},
		},
		{
			name: "marker failure detaches actual mount",
			setup: func(t *testing.T, detachLog string) (string, string) {
				actualMount := filepath.Join(t.TempDir(), "missing-parent", "actual")
				t.Setenv("HDIUTIL_MOUNT", actualMount)
				t.Setenv("HDIUTIL_DETACH_LOG", detachLog)
				return filepath.Join(t.TempDir(), "requested"), actualMount
			},
			wantErr: []string{"spotlight marker"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installFakeHdiutil(t)
			withDarwinCacheSeams(t, func(string) bool { return false }, nil)
			detachLog := filepath.Join(t.TempDir(), "detach.log")
			requestedMount, wantDetach := tc.setup(t, detachLog)
			_, err := provisionCaseSensitive(filepath.Join(t.TempDir(), "bundle"), requestedMount, "32m")
			if err == nil {
				t.Fatalf("provisionCaseSensitive succeeded, want error containing %v", tc.wantErr)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want substring %q", err, want)
				}
			}
			if wantDetach != "" {
				b, readErr := os.ReadFile(detachLog)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if !strings.Contains(string(b), wantDetach) {
					t.Fatalf("detach log = %q, want mount %s", b, wantDetach)
				}
			}
		})
	}
}

// TestParseMountpointDecodesXMLEntities pins entity decoding: hdiutil's plist
// escapes XML-special characters in the mount path (a store path may carry
// "&" or "'"), and the raw escaped form would make every later use of the
// path (markers, rootfs, detach) target a nonexistent location.
func TestParseMountpointDecodesXMLEntities(t *testing.T) {
	in := `<key>mount-point</key><string>/tmp/a &amp; b&#39;s store/mnt</string>`
	got, err := parseMountpoint(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := "/tmp/a & b's store/mnt"; got != want {
		t.Fatalf("parseMountpoint = %q, want %q", got, want)
	}
}
