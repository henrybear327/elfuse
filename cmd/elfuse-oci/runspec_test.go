// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1"
)

func TestResolveArgs(t *testing.T) {
	cases := []struct {
		name             string
		imgEntry, imgCmd []string
		cliEntry         string
		tail             []string
		want             []string
	}{
		{"image entry+cmd, no overrides", []string{"/ep"}, []string{"-c"}, "", nil, []string{"/ep", "-c"}},
		{"tail replaces cmd, keeps entry", []string{"/ep"}, []string{"-c"}, "", []string{"-x"}, []string{"/ep", "-x"}},
		{"--entrypoint clobbers entry+cmd, no tail", []string{"/ep"}, []string{"-c"}, "/new", nil, []string{"/new"}},
		{"--entrypoint + tail", []string{"/ep"}, []string{"-c"}, "/new", []string{"-x"}, []string{"/new", "-x"}},
		{"no entrypoint, image cmd", nil, []string{"/bin/sh"}, "", nil, []string{"/bin/sh"}},
		{"no entrypoint, tail replaces cmd", nil, []string{"/bin/sh"}, "", []string{"/bin/echo", "hi"}, []string{"/bin/echo", "hi"}},
		{"nothing at all", nil, nil, "", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveArgs(c.imgEntry, c.imgCmd, c.cliEntry, c.tail)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("resolveArgs: got %v, want %v", got, c.want)
			}
		})
	}
}

func TestResolveEnv(t *testing.T) {
	t.Setenv("ELFUSE_TEST_HOST", "from-host")
	cases := []struct {
		name      string
		imgEnv    []string
		overrides []string
		clearEnv  bool
		want      []string
	}{
		{"image env only", []string{"A=1", "B=2"}, nil, false, []string{"A=1", "B=2"}},
		{"override existing", []string{"A=1"}, []string{"A=9"}, false, []string{"A=9"}},
		{"append new", []string{"A=1"}, []string{"B=2"}, false, []string{"A=1", "B=2"}},
		{"clear-env drops image env", []string{"A=1"}, []string{"B=2"}, true, []string{"B=2"}},
		{"bare KEY inherits host", []string{"A=1"}, []string{"ELFUSE_TEST_HOST"}, false, []string{"A=1", "ELFUSE_TEST_HOST=from-host"}},
		{"bare KEY unset on host is skipped", []string{"A=1"}, []string{"DEFINITELY_UNSET_XYZ"}, false, []string{"A=1"}},
		{"empty-key image entry dropped", []string{"=1", "A=2"}, nil, false, []string{"A=2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveEnv(c.imgEnv, c.overrides, c.clearEnv)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("resolveEnv: got %v, want %v", got, c.want)
			}
		})
	}
}

func TestResolveUser(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(
		"root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte(
		"root:x:0:\nbin:x:1:\nstaff:x:20:\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		spec    string
		wantUID uint32
		wantGID uint32
		wantErr bool
	}{
		{"empty is root", "", 0, 0, false},
		{"root name", "root", 0, 0, false},
		{"bare numeric uid defaults gid=uid", "1000", 1000, 1000, false},
		{"numeric uid:gid", "1000:20", 1000, 20, false},
		{"name from passwd", "bin", 1, 1, false},
		{"name:group", "bin:staff", 1, 20, false},
		{"name:numeric gid", "bin:99", 1, 99, false},
		{"unknown user errors", "ghost", 0, 0, true},
		{"unknown group errors", "bin:ghost", 0, 0, true},
		{"root:group resolves the group part", "root:staff", 0, 20, false},
		{"root with unknown group errors", "root:ghost", 0, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			uid, gid, err := resolveUser(root, c.spec)
			if (err != nil) != c.wantErr {
				t.Fatalf("resolveUser(%q): err=%v, wantErr=%v", c.spec, err, c.wantErr)
			}
			if c.wantErr {
				return
			}
			if uid != c.wantUID || gid != c.wantGID {
				t.Errorf("resolveUser(%q): uid=%d gid=%d, want %d:%d", c.spec, uid, gid, c.wantUID, c.wantGID)
			}
		})
	}
}

// TestResolveUserRootGidFromPasswd pins that "root" resolves through
// /etc/passwd like any other name: a root entry with a non-zero gid wins
// over the 0:0 fallback.
func TestResolveUserRootGidFromPasswd(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(
		"root:x:0:50:root:/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	uid, gid, err := resolveUser(root, "root")
	if err != nil {
		t.Fatalf("resolveUser(root): %v", err)
	}
	if uid != 0 || gid != 50 {
		t.Errorf("resolveUser(root): uid=%d gid=%d, want 0:50", uid, gid)
	}
}

// TestResolveUserRootWithoutPasswd pins the FROM scratch fallback: with no
// readable /etc/passwd (or one lacking a root entry), "root" must resolve
// to 0:0 instead of erroring.
func TestResolveUserRootWithoutPasswd(t *testing.T) {
	cases := []struct {
		name   string
		passwd string // written to etc/passwd when non-empty
	}{
		{"no passwd", ""},
		{"no root entry", "bin:x:1:1:bin:/bin:/sbin/nologin\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			if c.passwd != "" {
				if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(c.passwd), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			uid, gid, err := resolveUser(root, "root")
			if err != nil {
				t.Fatalf("resolveUser(root): %v", err)
			}
			if uid != 0 || gid != 0 {
				t.Errorf("resolveUser(root): uid=%d gid=%d, want 0:0", uid, gid)
			}
		})
	}
}

func TestLookupPasswdScannerError(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	longLine := strings.Repeat("x", bufio.MaxScanTokenSize+1)
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(longLine), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := lookupPasswd(root, "root")
	if err == nil || !strings.Contains(err.Error(), "scan /etc/passwd") {
		t.Fatalf("lookupPasswd err = %v, want scan /etc/passwd error", err)
	}
}

// TestLookupPasswdRejectsSymlinkEscape pins the rootfs-bounded open: an image
// whose etc/passwd is a symlink to a file outside the rootfs must not have
// user resolution read that host file.
func TestLookupPasswdRejectsSymlinkEscape(t *testing.T) {
	outside := t.TempDir()
	hostPasswd := filepath.Join(outside, "passwd")
	if err := os.WriteFile(hostPasswd, []byte("evil:x:0:0::/:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hostPasswd, filepath.Join(root, "etc", "passwd")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lookupPasswd(root, "evil"); err == nil {
		t.Fatal("lookupPasswd resolved a user through a symlink escaping the rootfs")
	}

	if err := os.Symlink(hostPasswd, filepath.Join(root, "etc", "group")); err != nil {
		t.Fatal(err)
	}
	if _, err := lookupGroup(root, "evil"); err == nil {
		t.Fatal("lookupGroup resolved a group through a symlink escaping the rootfs")
	}
}

func TestLookupGroupScannerError(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	longLine := strings.Repeat("x", bufio.MaxScanTokenSize+1)
	if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte(longLine), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := lookupGroup(root, "root")
	if err == nil || !strings.Contains(err.Error(), "scan /etc/group") {
		t.Fatalf("lookupGroup err = %v, want scan /etc/group error", err)
	}
}

// TestComputeRunSpecNoCommand exercises the empty-command error branch: no
// image Entrypoint/Cmd and no --entrypoint/tail yields an error. computeRunSpec
// takes a *v1.ConfigFile directly, so no real image is needed; with User empty,
// resolveUser returns 0:0 without touching /etc/passwd.
func TestComputeRunSpecNoCommand(t *testing.T) {
	cfg := &v1.ConfigFile{Config: v1.Config{}} // no Entrypoint, no Cmd
	if _, err := computeRunSpec(cfg, runFlags{}, t.TempDir(), nil); err == nil ||
		!strings.Contains(err.Error(), "no command") {
		t.Fatalf("err=%v, want an error containing %q", err, "no command")
	}
}

// TestComputeRunSpecWorkdirNotAbsolute covers the non-absolute workdir error
// branch. The command check (runspec.go:73) runs before the workdir check
// (:89), so the config must carry a valid Cmd to reach it. A subtest covers
// the image-config WorkingDir path too.
func TestComputeRunSpecWorkdirNotAbsolute(t *testing.T) {
	t.Run("flag workdir", func(t *testing.T) {
		cfg := &v1.ConfigFile{Config: v1.Config{Cmd: []string{"/hello"}}}
		rf := runFlags{workdir: "relative/path"}
		_, err := computeRunSpec(cfg, rf, t.TempDir(), nil)
		if err == nil || !strings.Contains(err.Error(), "not guest-absolute") {
			t.Fatalf("err=%v, want an error containing %q", err, "not guest-absolute")
		}
	})
	t.Run("image workdir", func(t *testing.T) {
		cfg := &v1.ConfigFile{Config: v1.Config{Cmd: []string{"/hello"}, WorkingDir: "rel"}}
		_, err := computeRunSpec(cfg, runFlags{}, t.TempDir(), nil)
		if err == nil || !strings.Contains(err.Error(), "not guest-absolute") {
			t.Fatalf("err=%v, want an error containing %q", err, "not guest-absolute")
		}
	})
}

func writeUserFiles(t *testing.T, root, passwd, group string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(passwd), 0o644); err != nil {
		t.Fatal(err)
	}
	if group != "" {
		if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte(group), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestComputeRunSpecRelativeEntrypoint pins the Docker rules for exec-form
// commands: a relative path entrypoint (contains a slash) resolves against
// the working directory, and a bare name resolves via the merged PATH inside
// the image rootfs. elfuse resolves the initial ELF before chdiring to
// --workdir and does no PATH lookup, so both must happen in the spec.
func TestComputeRunSpecRelativeEntrypoint(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "usr", "bin", "node"), []byte("#!"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		args    []string
		want    string
		wantErr string
	}{
		{"dot-relative", []string{"./server"}, "/app/server", ""},
		{"subdir-relative", []string{"bin/tool"}, "/app/bin/tool", ""},
		{"bare name via image PATH", []string{"node"}, "/usr/bin/node", ""},
		{"bare name absent", []string{"missing"}, "", "not found in image PATH"},
		{"absolute untouched", []string{"/entry"}, "/entry", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &v1.ConfigFile{Config: v1.Config{
				Entrypoint: tc.args,
				WorkingDir: "/app",
			}}
			spec, err := computeRunSpec(cfg, runFlags{}, rootfs, nil)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if spec.Args[0] != tc.want {
				t.Errorf("Args[0] = %q, want %q", spec.Args[0], tc.want)
			}
		})
	}
}
func TestComputeRunSpecSuccessFullPrecedence(t *testing.T) {
	root := t.TempDir()
	writeUserFiles(t, root,
		"root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin\n",
		"root:x:0:\nstaff:x:20:\n",
	)
	cfg := &v1.ConfigFile{Config: v1.Config{
		Entrypoint: []string{"/entry"},
		Cmd:        []string{"image-cmd"},
		Env:        []string{"A=1", "B=2"},
		WorkingDir: "/image-workdir",
		User:       "root",
	}}
	rf := runFlags{
		env:     []string{"B=9", "C=3"},
		workdir: "/flag-workdir",
		user:    "bin:staff",
	}
	spec, err := computeRunSpec(cfg, rf, root, []string{"tail-cmd", "arg"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(spec.Args, []string{"/entry", "tail-cmd", "arg"}) {
		t.Fatalf("Args = %v, want entrypoint plus CLI tail", spec.Args)
	}
	if !reflect.DeepEqual(spec.Env, []string{"A=1", "B=9", "C=3", "PATH=" + defaultGuestPath}) {
		t.Fatalf("Env = %v, want ordered override plus default PATH", spec.Env)
	}
	if spec.Workdir != "/flag-workdir" {
		t.Fatalf("Workdir = %q, want flag workdir", spec.Workdir)
	}
	if spec.UID != 1 || spec.GID != 20 {
		t.Fatalf("UID:GID = %d:%d, want 1:20", spec.UID, spec.GID)
	}
}

// TestComputeRunSpecDefaultPath pins the PATH guarantee: the guest always
// receives a PATH, the image's own PATH is never rewritten, and an --env
// override wins over both.
func TestComputeRunSpecDefaultPath(t *testing.T) {
	cases := []struct {
		name     string
		imgEnv   []string
		env      []string
		clearEnv bool
		want     []string
	}{
		{"no PATH anywhere gets the default", []string{"A=1"}, nil, false,
			[]string{"A=1", "PATH=" + defaultGuestPath}},
		{"image PATH is preserved", []string{"PATH=/opt/bin"}, nil, false,
			[]string{"PATH=/opt/bin"}},
		{"--env PATH wins", []string{"PATH=/opt/bin"}, []string{"PATH=/bin"}, false,
			[]string{"PATH=/bin"}},
		{"--clear-env still yields a PATH", []string{"PATH=/opt/bin"}, nil, true,
			[]string{"PATH=" + defaultGuestPath}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &v1.ConfigFile{Config: v1.Config{
				Cmd: []string{"/bin/true"},
				Env: c.imgEnv,
			}}
			rf := runFlags{env: c.env, clearEnv: c.clearEnv}
			spec, err := computeRunSpec(cfg, rf, t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(spec.Env, c.want) {
				t.Errorf("Env = %v, want %v", spec.Env, c.want)
			}
		})
	}
}

func TestResolveArgsDoesNotMutateInputs(t *testing.T) {
	entry := []string{"/entry"}
	cmd := []string{"image-cmd"}
	tail := []string{"tail"}
	got := resolveArgs(entry, cmd, "", tail)
	got[0] = "/changed"
	if !reflect.DeepEqual(entry, []string{"/entry"}) {
		t.Fatalf("entry mutated to %v", entry)
	}
	if !reflect.DeepEqual(cmd, []string{"image-cmd"}) {
		t.Fatalf("cmd mutated to %v", cmd)
	}
	if !reflect.DeepEqual(tail, []string{"tail"}) {
		t.Fatalf("tail mutated to %v", tail)
	}
}

func TestResolveEnvDuplicateOrdering(t *testing.T) {
	got := resolveEnv([]string{"A=1", "B=2"}, []string{"A=3", "C=4", "B=5"}, false)
	want := []string{"A=3", "B=5", "C=4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveEnv = %v, want %v", got, want)
	}
}

func TestResolveUserErrorBranches(t *testing.T) {
	cases := []struct {
		name    string
		passwd  string // when empty, /etc/passwd is not written
		group   string // when empty, /etc/group is not written
		user    string
		wantErr string
	}{
		{"missing passwd", "", "", "bin", "open /etc/passwd"},
		{"bad passwd uid", "bin:x:not-a-uid:1:bin:/bin:/bin/sh\n", "", "bin", "bad uid"},
		{"bad passwd gid", "bin:x:1:not-a-gid:bin:/bin:/bin/sh\n", "", "bin", "bad gid"},
		{"missing group", "bin:x:1:1:bin:/bin:/bin/sh\n", "", "bin:staff", "open /etc/group"},
		{"bad group gid", "bin:x:1:1:bin:/bin:/bin/sh\n", "staff:x:not-a-gid:\n", "bin:staff", "bad gid"},
		{"numeric uid overflow", "", "", strings.Repeat("9", 20), "invalid uid"},
		{"numeric gid overflow", "", "", "1:" + strings.Repeat("9", 20), "invalid gid"},
		{"empty user part", "bin:x:1:1:bin:/bin:/bin/sh\n", "staff:x:20:\n", ":staff", `resolve user ""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.passwd != "" {
				writeUserFiles(t, root, tc.passwd, tc.group)
			}
			_, _, err := resolveUser(root, tc.user)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("resolveUser(%q) err = %v, want %q", tc.user, err, tc.wantErr)
			}
		})
	}
}
