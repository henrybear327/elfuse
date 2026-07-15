// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInjectRuntimeFiles asserts the three runtime files are written with the
// expected shape, and that a second call overwrites (not appends).
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

	// Exactly the three runtime files: the temp-and-rename writes must not
	// leave *.tmp.* staging litter behind.
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

// TestWriteRuntimeFileLeavesNoTempOnFailure pins that a failed write does not
// leave a staging temp file behind.
func TestWriteRuntimeFileLeavesNoTempOnFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory write permissions do not bind as root")
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if err := writeRuntimeFile(root, "resolv.conf", []byte("nameserver 8.8.8.8\n")); err == nil {
		t.Fatal("writeRuntimeFile into read-only dir succeeded, want error")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed write left litter: %v", entries)
	}
}

// TestInjectRuntimeFilesReplacesSymlinkEtc pins the symlink guard: a stray
// /etc symlink (e.g. from a malformed image) is replaced with a real directory
// so the writes cannot escape the rootfs.
func TestInjectRuntimeFilesReplacesSymlinkEtc(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	etcLink := filepath.Join(root, "etc")
	if err := os.Symlink(target, etcLink); err != nil {
		t.Fatal(err)
	}

	if err := injectRuntimeFiles(root); err != nil {
		t.Fatal(err)
	}

	li, err := os.Lstat(etcLink)
	if err != nil {
		t.Fatalf("Lstat etc: %v", err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("etc is still a symlink: mode %o", li.Mode())
	}
	if !li.IsDir() {
		t.Fatalf("etc is not a directory: mode %o", li.Mode())
	}
	for _, name := range []string{"hostname", "hosts", "resolv.conf"} {
		if _, err := os.Stat(filepath.Join(etcLink, name)); err != nil {
			t.Errorf("etc/%s missing after symlink replacement: %v", name, err)
		}
	}
	// The symlink target directory must not have received the files.
	if _, err := os.Stat(filepath.Join(target, "hostname")); err == nil {
		t.Error("hostname leaked into the symlink target directory")
	}
}

// TestInjectRuntimeFilesReplacesSymlinkTargets asserts that a symlink shipped
// by the image AT a runtime file's own name (etc/resolv.conf -> host path) is
// replaced with a regular file rather than followed: the write must not land
// in the symlink's target outside the rootfs.
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

func TestInjectRuntimeFilesFilesystemErrors(t *testing.T) {
	rootFile := filepath.Join(t.TempDir(), "sysroot-file")
	if err := os.WriteFile(rootFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := injectRuntimeFiles(rootFile); err == nil {
		t.Fatal("injectRuntimeFiles with file sysroot succeeded, want error")
	}
}

// TestInjectRuntimeFilesRejectsRegularFileEtc pins the up-front check: an
// image shipping /etc as a regular file must fail with a clear error, not a
// confusing "not a directory" from the first runtime-file write.
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

// TestEnsureWorkdir pins the config-only WORKDIR behavior: a working
// directory no layer ships is created at run time (as runc does), while an
// existing path, including one reached through an image symlink, is left
// untouched.
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
