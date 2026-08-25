// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// TestResolveArgs pins Docker's Entrypoint/Cmd precedence for every
// override combination.
func TestResolveArgs(t *testing.T) {
	cases := []struct {
		name             string
		imgEntry, imgCmd []string
		cliEntry         string
		entrySet         bool
		tail             []string
		want             []string
	}{
		{"image entry+cmd, no overrides", []string{"/ep"}, []string{"-c"}, "", false, nil, []string{"/ep", "-c"}},
		{"tail replaces cmd, keeps entry", []string{"/ep"}, []string{"-c"}, "", false, []string{"-x"}, []string{"/ep", "-x"}},
		{"--entrypoint clobbers entry+cmd, no tail", []string{"/ep"}, []string{"-c"}, "/new", true, nil, []string{"/new"}},
		{"--entrypoint + tail", []string{"/ep"}, []string{"-c"}, "/new", true, []string{"-x"}, []string{"/new", "-x"}},
		{"--entrypoint \"\" clears entry, tail runs alone", []string{"/ep"}, []string{"-c"}, "", true, []string{"-x"}, []string{"-x"}},
		{"--entrypoint \"\" clears entry, image cmd runs", []string{"/ep"}, []string{"-c"}, "", true, nil, []string{"-c"}},
		{"no entrypoint, image cmd", nil, []string{"/bin/sh"}, "", false, nil, []string{"/bin/sh"}},
		{"no entrypoint, tail replaces cmd", nil, []string{"/bin/sh"}, "", false, []string{"/bin/echo", "hi"}, []string{"/bin/echo", "hi"}},
		{"nothing at all", nil, nil, "", false, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveArgs(c.imgEntry, c.imgCmd, c.cliEntry, c.entrySet, c.tail)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("resolveArgs: got %v, want %v", got, c.want)
			}
		})
	}
}

// TestResolveEnv pins the docker run -e merge: base, override, append,
// bare-KEY host inheritance, and empty-key dropping.
func TestResolveEnv(t *testing.T) {
	t.Setenv("ELFUSE_TEST_HOST", "from-host")
	// The unset-KEY case must not depend on the ambient environment:
	// t.Setenv records the prior state for restore (and bars t.Parallel),
	// then the immediate Unsetenv guarantees the name is absent.
	t.Setenv("ELFUSE_TEST_UNSET", "")
	os.Unsetenv("ELFUSE_TEST_UNSET")
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
		{"bare KEY unset on host is skipped", []string{"A=1"}, []string{"ELFUSE_TEST_UNSET"}, false, []string{"A=1"}},
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

// TestResolveUser pins the image-config User grammar: numeric and name
// specs, the :group part, and gid defaulting to uid for bare numerics.
func TestResolveUser(t *testing.T) {
	root := t.TempDir()
	writeUserFiles(t, root,
		"root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n",
		"root:x:0:\nbin:x:1:\nstaff:x:20:\n")

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

// TestResolveUserRoot pins "root" resolution: passwd-first (a non-zero
// gid wins) with a 0:0 fallback when passwd is missing or lacks a root
// entry.
func TestResolveUserRoot(t *testing.T) {
	cases := []struct {
		name    string
		passwd  string // written to etc/passwd when non-empty
		wantUID uint32
		wantGID uint32
	}{
		{"root gid from passwd", "root:x:0:50:root:/root:/bin/sh\n", 0, 50},
		{"no passwd", "", 0, 0},
		{"no root entry", "bin:x:1:1:bin:/bin:/sbin/nologin\n", 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeUserFiles(t, root, c.passwd, "")
			uid, gid, err := resolveUser(root, "root")
			if err != nil {
				t.Fatalf("resolveUser(root): %v", err)
			}
			if uid != c.wantUID || gid != c.wantGID {
				t.Errorf("resolveUser(root): uid=%d gid=%d, want %d:%d", uid, gid, c.wantUID, c.wantGID)
			}
		})
	}
}

// A line past the default 64KB token size scans (real group files get
// that long); one past the 1MiB cap errors rather than resolving from a
// half-read file.
func TestLookupScannerErrors(t *testing.T) {
	longLine := strings.Repeat("x", 1024*1024+1)
	cases := []struct {
		name string
		want string
		call func(root string) error
	}{
		{"passwd", "scan /etc/passwd", func(root string) error {
			_, _, err := lookupPasswd(root, "root")
			return err
		}},
		{"group", "scan /etc/group", func(root string) error {
			_, err := lookupGroup(root, "root")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			passwd, group := longLine, ""
			if tc.name == "group" {
				passwd, group = "", longLine
			}
			writeUserFiles(t, root, passwd, group)
			if err := tc.call(root); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s err = %v, want %q", tc.name, err, tc.want)
			}
		})
	}
	t.Run("long-line-tolerated", func(t *testing.T) {
		root := t.TempDir()
		junk := "big:" + strings.Repeat("x", 100*1024)
		writeUserFiles(t, root, junk+"\napp:x:7:9:/:/bin/sh", "")
		uid, gid, err := lookupPasswd(root, "app")
		if err != nil || uid != 7 || gid != 9 {
			t.Fatalf("entry after a 100KB line = %d:%d, %v", uid, gid, err)
		}
	})
}

// TestLookupPasswdRejectsSymlinkEscape pins openInRootfs confinement: a
// symlinked etc/passwd or etc/group must not read host account files.
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

// TestComputeRunSpecNoCommand pins the empty-command error.
func TestComputeRunSpecNoCommand(t *testing.T) {
	cfg := ocispec.Image{Config: ocispec.ImageConfig{}} // no Entrypoint, no Cmd
	if _, err := computeRunSpec(cfg, runFlags{}, t.TempDir(), nil); err == nil ||
		!strings.Contains(err.Error(), "no command") {
		t.Fatalf("err=%v, want an error containing %q", err, "no command")
	}
}

// A relative image WorkingDir is refused; the --workdir form is
// validateRunFlags's.
func TestComputeRunSpecWorkdirNotAbsolute(t *testing.T) {
	cfg := ocispec.Image{Config: ocispec.ImageConfig{Cmd: []string{"/hello"}, WorkingDir: "rel"}}
	_, err := computeRunSpec(cfg, runFlags{}, t.TempDir(), nil)
	if err == nil || !strings.Contains(err.Error(), "not guest-absolute") {
		t.Fatalf("err=%v, want an error containing %q", err, "not guest-absolute")
	}
}

// The rules decidable from the flags alone, refused before any network
// work.
func TestValidateRunFlags(t *testing.T) {
	for _, tc := range []struct {
		rf   runFlags
		want string
	}{
		{runFlags{workdir: "relative/path"}, "not guest-absolute"},
		{runFlags{env: []string{"=VAL"}}, "empty variable name"},
		{runFlags{env: []string{""}}, "empty variable name"},
		{runFlags{workdir: "/ok", env: []string{"A=1", "B"}}, ""},
		{runFlags{cs: csFlags{sparseSize: "16GB"}}, "invalid --sparse-size"},
		{runFlags{cs: csFlags{sparseSize: "g"}}, "invalid --sparse-size"},
		{runFlags{cs: csFlags{sparseSize: "1.5g"}}, ""},
		{runFlags{cs: csFlags{sparseSize: "32g"}}, ""},
		{runFlags{cs: csFlags{sparseSize: "4096"}}, ""},
	} {
		err := validateRunFlags(tc.rf)
		if tc.want == "" && err != nil {
			t.Errorf("%+v: unexpected %v", tc.rf, err)
		} else if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%+v: err=%v, want %q", tc.rf, err, tc.want)
		}
	}
}

// The workdir normalization: "//" folds and "/.." clamps at "/".
func TestComputeRunSpecWorkdirNormalized(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"//opt", "/opt"},
		{"/../opt", "/opt"},
		{"/app//nested/", "/app/nested"},
	} {
		cfg := ocispec.Image{Config: ocispec.ImageConfig{Cmd: []string{"/hello"}}}
		spec, err := computeRunSpec(cfg, runFlags{workdir: c.in}, t.TempDir(), nil)
		if err != nil {
			t.Fatalf("workdir %q: %v", c.in, err)
		}
		if spec.Workdir != c.want {
			t.Errorf("workdir %q: got %q, want %q", c.in, spec.Workdir, c.want)
		}
	}
}

// writeUserFiles seeds root/etc with the given passwd and group contents,
// writing each file only when its content is non-empty so callers can model
// an image that ships one, both, or neither.
func writeUserFiles(t *testing.T, root, passwd, group string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if passwd != "" {
		if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(passwd), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if group != "" {
		if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte(group), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestComputeRunSpecRelativeEntrypoint pins workdir-relative and PATH
// command resolution; see the Docker-resolution note in computeRunSpec.
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
			cfg := ocispec.Image{Config: ocispec.ImageConfig{
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

// TestComputeRunSpecRelativePathEntries pins empty and relative PATH
// elements resolving against the working directory; see lookPathInRootfs.
func TestComputeRunSpecRelativePathEntries(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "app", "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(rootfs, "app", "server"),
		filepath.Join(rootfs, "app", "tools", "helper"),
	} {
		if err := os.WriteFile(p, []byte("#!"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		path string
		cmd  string
		want string
	}{
		{"empty entry means workdir", "PATH=:/bin", "server", "/app/server"},
		{"relative entry joins workdir", "PATH=tools:/bin", "helper", "/app/tools/helper"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ocispec.Image{Config: ocispec.ImageConfig{
				Entrypoint: []string{tc.cmd},
				Env:        []string{tc.path},
				WorkingDir: "/app",
			}}
			spec, err := computeRunSpec(cfg, runFlags{}, rootfs, nil)
			if err != nil {
				t.Fatal(err)
			}
			if spec.Args[0] != tc.want {
				t.Errorf("Args[0] = %q, want %q", spec.Args[0], tc.want)
			}
		})
	}
}

// TestComputeRunSpecSuccessFullPrecedence pins every CLI-over-image
// precedence in one spec.
func TestComputeRunSpecSuccessFullPrecedence(t *testing.T) {
	root := t.TempDir()
	writeUserFiles(t, root,
		"root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin\n",
		"root:x:0:\nstaff:x:20:\n",
	)
	cfg := ocispec.Image{Config: ocispec.ImageConfig{
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

// TestComputeRunSpecDefaultPath pins the PATH guarantee: always present,
// image PATH preserved, --env PATH winning.
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
			cfg := ocispec.Image{Config: ocispec.ImageConfig{
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

// TestResolveArgsDoesNotMutateInputs pins that resolveArgs returns a fresh
// slice: its inputs alias the parsed image config, which the caller reads
// again after the merge, so an in-place append would corrupt later reads.
func TestResolveArgsDoesNotMutateInputs(t *testing.T) {
	entry := []string{"/entry"}
	cmd := []string{"image-cmd"}
	tail := []string{"tail"}
	got := resolveArgs(entry, cmd, "", false, tail)
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

// TestResolveEnvDuplicateOrdering pins override positioning: a replaced
// key keeps the base position and a new key appends, as env(1) and docker
// do.
func TestResolveEnvDuplicateOrdering(t *testing.T) {
	got := resolveEnv([]string{"A=1", "B=2"}, []string{"A=3", "C=4", "B=5"}, false)
	want := []string{"A=3", "B=5", "C=4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveEnv = %v, want %v", got, want)
	}
}

// TestResolveUserErrorBranches pins that malformed or unreadable
// passwd/group data errors instead of falling back to a wrong identity.
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
		{"empty user part", "bin:x:1:1:bin:/bin:/bin/sh\n", "staff:x:20:\n", ":staff", "want UID[:GID]"},
		{"empty group part", "bin:x:1:1:bin:/bin:/bin/sh\n", "staff:x:20:\n", "1000:", "want UID[:GID]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeUserFiles(t, root, tc.passwd, tc.group)
			_, _, err := resolveUser(root, tc.user)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("resolveUser(%q) err = %v, want %q", tc.user, err, tc.wantErr)
			}
		})
	}
}

// refuseCSFlags: a sparsebundle-only flag off that path is refused with
// the reason this host gives, and --keep without a clone has nothing to
// keep.
func TestRefuseCSFlags(t *testing.T) {
	for _, c := range []struct {
		cs    csFlags
		useCS bool
		want  string
	}{
		{csFlags{}, false, ""},
		{csFlags{noClone: true}, true, ""},
		{csFlags{noClone: true}, false, "needs the sparsebundle path"},
		{csFlags{keepRootfs: true, noClone: true}, true, "--keep needs a clone"},
	} {
		err := refuseCSFlags(c.cs, c.useCS)
		if c.want == "" && err != nil {
			t.Errorf("%+v useCS=%v: unexpected %v", c.cs, c.useCS, err)
		} else if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%+v useCS=%v: err = %v, want %q", c.cs, c.useCS, err, c.want)
		}
	}
	if !csAvailable {
		if err := refuseCSFlags(csFlags{noClone: true}, false); err == nil || !strings.Contains(err.Error(), "requires macOS") {
			t.Errorf("off darwin the refusal must name the OS: %v", err)
		}
	}
}
