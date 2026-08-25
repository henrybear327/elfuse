// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestInjectRuntimeFiles pins that hostname, hosts, and resolv.conf exist
// with a usable shape and that re-injection replaces rather than appends.
func TestInjectRuntimeFiles(t *testing.T) {
	root := t.TempDir()
	if err := injectRuntimeFiles(root); err != nil {
		t.Fatal(err)
	}

	host, err := os.ReadFile(filepath.Join(root, "etc", "hostname"))
	if err != nil {
		t.Fatalf("hostname: %v", err)
	}
	hostname := strings.TrimSpace(string(host))
	if hostname == "" {
		t.Error("hostname is empty")
	}

	hosts, err := os.ReadFile(filepath.Join(root, "etc", "hosts"))
	if err != nil {
		t.Fatalf("hosts: %v", err)
	}
	hs := string(hosts)
	if !strings.Contains(hs, "127.0.0.1\tlocalhost") {
		t.Errorf("hosts missing 127.0.0.1 localhost: %q", hs)
	}
	if !strings.Contains(hs, "::1\tlocalhost") {
		t.Errorf("hosts missing ::1 localhost: %q", hs)
	}
	if !strings.Contains(hs, hostname) {
		t.Errorf("hosts missing hostname %q: %q", hostname, hs)
	}

	resolv, err := os.ReadFile(filepath.Join(root, "etc", "resolv.conf"))
	if err != nil {
		t.Fatalf("resolv.conf: %v", err)
	}
	// Substring only: the host's nameserver varies across macOS/Linux CI, and
	// the fallback is "nameserver 8.8.8.8"; either way a nameserver line is
	// present.
	if !strings.Contains(string(resolv), "nameserver") {
		t.Errorf("resolv.conf missing nameserver: %q", resolv)
	}

	// Second call overwrites in place, never appends: hostname stays the same.
	if err := injectRuntimeFiles(root); err != nil {
		t.Fatal(err)
	}
	host2, _ := os.ReadFile(filepath.Join(root, "etc", "hostname"))
	if strings.TrimSpace(string(host2)) != hostname {
		t.Errorf("hostname changed on re-inject: got %q want %q", host2, host)
	}

	// Exactly the three runtime files: no *.tmp.* staging files left behind.
	entries, err := os.ReadDir(filepath.Join(root, "etc"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("etc entries = %v, want exactly hostname, hosts, resolv.conf", names)
	}
}

// TestInjectRuntimeFilesRejectsAbsoluteEtcSymlink pins the refusal of an
// absolute-target /etc symlink, the link surviving the refusal; see the
// symlink-follow note in injectRuntimeFiles.
func TestInjectRuntimeFilesRejectsAbsoluteEtcSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "etc")); err != nil {
		t.Fatal(err)
	}

	err := injectRuntimeFiles(root)
	if err == nil || !strings.Contains(err.Error(), "does not resolve") {
		t.Fatalf("injectRuntimeFiles err = %v, want absolute-symlink refusal", err)
	}
	if li, lerr := os.Lstat(filepath.Join(root, "etc")); lerr != nil ||
		li.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("/etc altered by the refused injection: %v %v", li, lerr)
	}
}

// TestInjectRuntimeFilesReplacesSymlinkTargets pins that an image symlink
// at a runtime file's name is replaced, never followed to its target.
func TestInjectRuntimeFilesReplacesSymlinkTargets(t *testing.T) {
	outside := t.TempDir()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}

	const sentinel = "host-owned\n"
	for _, name := range []string{"hostname", "hosts", "resolv.conf"} {
		hostFile := filepath.Join(outside, name)
		if err := os.WriteFile(hostFile, []byte(sentinel), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(hostFile, filepath.Join(root, "etc", name)); err != nil {
			t.Fatal(err)
		}
	}

	if err := injectRuntimeFiles(root); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"hostname", "hosts", "resolv.conf"} {
		li, err := os.Lstat(filepath.Join(root, "etc", name))
		if err != nil {
			t.Fatalf("Lstat etc/%s: %v", name, err)
		}
		if li.Mode()&os.ModeSymlink != 0 {
			t.Errorf("etc/%s is still a symlink after inject", name)
		}
		got, err := os.ReadFile(filepath.Join(outside, name))
		if err != nil {
			t.Fatalf("read outside %s: %v", name, err)
		}
		if string(got) != sentinel {
			t.Errorf("outside %s was overwritten through the symlink: %q", name, got)
		}
	}
}

// TestInjectRuntimeFilesFallbacks pins that host-introspection failures
// degrade to localhost and 8.8.8.8 rather than failing the run.
func TestInjectRuntimeFilesFallbacks(t *testing.T) {
	oldHostname := hostnameForRuntime
	oldReadResolv := readHostResolvConfig
	hostnameForRuntime = func() (string, error) { return "", errors.New("hostname unavailable") }
	readHostResolvConfig = func() ([]byte, error) { return nil, errors.New("resolv unavailable") }
	t.Cleanup(func() {
		hostnameForRuntime = oldHostname
		readHostResolvConfig = oldReadResolv
	})

	root := t.TempDir()
	if err := injectRuntimeFiles(root); err != nil {
		t.Fatal(err)
	}
	hostname, err := os.ReadFile(filepath.Join(root, "etc", "hostname"))
	if err != nil {
		t.Fatal(err)
	}
	if string(hostname) != "localhost\n" {
		t.Fatalf("fallback hostname = %q, want localhost", hostname)
	}
	hosts, err := os.ReadFile(filepath.Join(root, "etc", "hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hosts), "localhost") {
		t.Fatalf("fallback hosts = %q, want localhost mapping", hosts)
	}
	resolv, err := os.ReadFile(filepath.Join(root, "etc", "resolv.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(resolv) != "nameserver 8.8.8.8\n" {
		t.Fatalf("fallback resolv.conf = %q, want Google DNS fallback", resolv)
	}
}

// TestInjectRuntimeFilesFilesystemErrors pins that a file sysroot fails
// injection outright.
func TestInjectRuntimeFilesFilesystemErrors(t *testing.T) {
	rootFile := filepath.Join(t.TempDir(), "sysroot-file")
	if err := os.WriteFile(rootFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := injectRuntimeFiles(rootFile); err == nil {
		t.Fatal("injectRuntimeFiles with file sysroot succeeded, want error")
	}
}

// TestInjectRuntimeFilesRejectsRegularFileEtc pins the up-front /etc
// guard and its clear error; see the guard note in injectRuntimeFiles.
func TestInjectRuntimeFilesRejectsRegularFileEtc(t *testing.T) {
	sysroot := t.TempDir()
	if err := os.WriteFile(filepath.Join(sysroot, "etc"), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := injectRuntimeFiles(sysroot)
	if err == nil || !strings.Contains(err.Error(), "want a directory") {
		t.Fatalf("injectRuntimeFiles err = %v, want explicit non-directory /etc error", err)
	}
	if b, rerr := os.ReadFile(filepath.Join(sysroot, "etc")); rerr != nil || string(b) != "not a dir" {
		t.Fatalf("etc file after rejection = %q, err=%v; want untouched", b, rerr)
	}
}

// TestEnsureWorkdir pins ensureWorkdir's contract: create when missing,
// leave existing directories and symlinks untouched.
func TestEnsureWorkdir(t *testing.T) {
	t.Run("creates missing", func(t *testing.T) {
		rootfs := t.TempDir()
		if err := ensureWorkdir(rootfs, "/app/nested"); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(filepath.Join(rootfs, "app", "nested"))
		if err != nil || !fi.IsDir() {
			t.Fatalf("workdir not created: fi=%v err=%v", fi, err)
		}
	})
	t.Run("root is a no-op", func(t *testing.T) {
		if err := ensureWorkdir(t.TempDir(), "/"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("existing symlink kept", func(t *testing.T) {
		rootfs := t.TempDir()
		if err := os.Mkdir(filepath.Join(rootfs, "real"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(rootfs, "app")); err != nil {
			t.Fatal(err)
		}
		if err := ensureWorkdir(rootfs, "/app"); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(filepath.Join(rootfs, "app"))
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("existing symlink replaced: fi=%v err=%v", fi, err)
		}
	})
}

func TestEnsureWorkdirRejectsExistingFile(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootfs, "app"), []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := ensureWorkdir(rootfs, "/app")
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("ensureWorkdir error = %v, want ENOTDIR", err)
	}
}

// TestInjectRuntimeFilesFollowsEtcSymlink pins that a rootfs-internal
// /etc symlink is followed, confined, with the image's /etc content
// surviving; see the symlink-follow note in injectRuntimeFiles.
func TestInjectRuntimeFilesFollowsEtcSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "private", "etc")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "passwd")
	if err := os.WriteFile(sentinel, []byte("root:x:0:0::/:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("private", "etc"), filepath.Join(root, "etc")); err != nil {
		t.Fatal(err)
	}

	if err := injectRuntimeFiles(root); err != nil {
		t.Fatal(err)
	}

	li, err := os.Lstat(filepath.Join(root, "etc"))
	if err != nil {
		t.Fatal(err)
	}
	if li.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("/etc symlink was replaced with a %s", li.Mode().Type())
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("image /etc content dropped: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "resolv.conf")); err != nil {
		t.Fatalf("injected file did not land through the link: %v", err)
	}
}
