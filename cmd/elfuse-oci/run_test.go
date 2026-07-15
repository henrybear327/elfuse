// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeElfuseStub writes a #!/bin/sh stub script that stands in for the
// elfuse binary, and points elfuseBin() at it via $ELFUSE_BIN. spawnElfuseWait
// exec.Command's whatever $ELFUSE_BIN names, so no real elfuse (and no HVF) is
// needed. t.Setenv restores the env on cleanup.
func writeElfuseStub(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "elfuse-stub.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELFUSE_BIN", p)
	return p
}

// TestSpawnElfuseWaitExitCode verifies the child's exit code is returned as-is.
func TestSpawnElfuseWaitExitCode(t *testing.T) {
	writeElfuseStub(t, "exit 42")
	spec := &runSpec{Args: []string{"/hello"}, Workdir: "/", UID: 0, GID: 0}
	code, err := spawnElfuseWait(t.TempDir(), spec)
	if err != nil {
		t.Fatalf("spawnElfuseWait: %v", err)
	}
	if code != 42 {
		t.Errorf("exit code: got %d, want 42", code)
	}
}

// TestSpawnElfuseWaitSignalDeath verifies signal death is reported the
// shell-style way: 128 + signal. The child kills itself with SIGTERM (15), so
// cmd.Wait() observes WaitStatus.Signaled() independently of elfuse-oci's own
// signal forwarding.
func TestSpawnElfuseWaitSignalDeath(t *testing.T) {
	writeElfuseStub(t, "kill -TERM $$")
	spec := &runSpec{Args: []string{"/hello"}, Workdir: "/", UID: 0, GID: 0}
	code, err := spawnElfuseWait(t.TempDir(), spec)
	if err != nil {
		t.Fatalf("spawnElfuseWait: %v", err)
	}
	if code != 143 { // 128 + SIGTERM(15)
		t.Errorf("signal death: got %d, want 143 (128+15)", code)
	}
}

// TestElfuseArgvShape verifies the argv handed to elfuse is exactly
// elfuseArgv(rootfs, spec) minus the leading "elfuse" program-name (exec.Command
// prepends the binary path as argv[0], so spawnElfuseWait drops elfuseArgv[0]).
// The stub records its own argv ($@, which excludes $0) one per line.
func TestElfuseArgvShape(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "argv.txt")
	t.Setenv("ELFUSE_ARGV_OUT", outPath)
	writeElfuseStub(t, `printf '%s\n' "$@" > "$ELFUSE_ARGV_OUT"`)

	rootfs := t.TempDir()
	spec := &runSpec{
		Args:    []string{"/bin/echo", "hi"},
		Env:     []string{"A=1", "B=2"},
		Workdir: "/work",
		UID:     1000,
		GID:     1000,
	}
	wantArgv := elfuseArgv(rootfs, spec)[1:]

	code, err := spawnElfuseWait(rootfs, spec)
	if err != nil {
		t.Fatalf("spawnElfuseWait: %v", err)
	}
	if code != 0 {
		t.Fatalf("stub exited %d, want 0", code)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read argv out: %v", err)
	}
	gotLines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if !reflect.DeepEqual(gotLines, wantArgv) {
		t.Errorf("argv:\n got %v\nwant %v", gotLines, wantArgv)
	}
}

func TestElfuseBinEnvAndFallback(t *testing.T) {
	want := filepath.Join(t.TempDir(), "elfuse-custom")
	t.Setenv("ELFUSE_BIN", want)
	got, err := elfuseBin()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("elfuseBin with env = %q, want %q", got, want)
	}

	t.Setenv("ELFUSE_BIN", "")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want = filepath.Join(filepath.Dir(exe), "elfuse")
	got, err = elfuseBin()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("elfuseBin fallback = %q, want %q", got, want)
	}
}

func TestExecElfuseMissingBinary(t *testing.T) {
	t.Setenv("ELFUSE_BIN", filepath.Join(t.TempDir(), "missing-elfuse"))
	err := execElfuse(t.TempDir(), &runSpec{Args: []string{"/bin/true"}, Workdir: "/", UID: 0, GID: 0})
	if err == nil || !strings.Contains(err.Error(), "elfuse binary not found") {
		t.Fatalf("execElfuse missing binary err = %v, want not found", err)
	}
}

func TestExecElfuseSuccessSubprocess(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "argv.txt")
	stub := filepath.Join(dir, "elfuse-stub.sh")
	body := "printf '%s\\n' \"$@\" > \"$ELFUSE_EXEC_ARGV_OUT\"\nexit 17\n"
	if err := os.WriteFile(stub, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(dir, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		"ELFUSE_EXEC_ELFUSE_TEST=1",
		"ELFUSE_BIN="+stub,
		"ELFUSE_EXEC_ROOTFS="+rootfs,
		"ELFUSE_EXEC_ARGV_OUT="+outPath,
	)
	err := cmd.Run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 17 {
		t.Fatalf("execElfuse subprocess err = %T %v, want stub exit 17", err, err)
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, want := range []string{"--sysroot", rootfs, "--user", "1:2", "--workdir", "/", "--clear-env", "--env", "A=1", "/bin/echo", "hi"} {
		if !strings.Contains(out, want) {
			t.Fatalf("exec argv missing %q in:\n%s", want, out)
		}
	}
}

func TestSpawnElfuseWaitMissingAndStartErrors(t *testing.T) {
	t.Setenv("ELFUSE_BIN", filepath.Join(t.TempDir(), "missing-elfuse"))
	if _, err := spawnElfuseWait(t.TempDir(), &runSpec{Args: []string{"/bin/true"}, Workdir: "/", UID: 0, GID: 0}); err == nil ||
		!strings.Contains(err.Error(), "elfuse binary not found") {
		t.Fatalf("spawn missing binary err = %v, want not found", err)
	}

	nonExecutable := filepath.Join(t.TempDir(), "elfuse-not-executable")
	if err := os.WriteFile(nonExecutable, []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELFUSE_BIN", nonExecutable)
	if _, err := spawnElfuseWait(t.TempDir(), &runSpec{Args: []string{"/bin/true"}, Workdir: "/", UID: 0, GID: 0}); err == nil ||
		!strings.Contains(err.Error(), "spawn") {
		t.Fatalf("spawn start err = %v, want spawn error", err)
	}
}

// TestElfuseArgvSeparatesGuestArgs pins the "--" end-of-options marker: the
// guest command comes from untrusted image config, so an Entrypoint that
// begins with "-" must arrive as guest argv, not be parsed as an elfuse
// option by the host launcher.
func TestElfuseArgvSeparatesGuestArgs(t *testing.T) {
	spec := &runSpec{
		Args:    []string{"--gdb", "1234"},
		Workdir: "/",
	}
	argv := elfuseArgv("/rootfs", spec)
	sep := -1
	for i, a := range argv {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		t.Fatalf("argv %v carries no \"--\" separator before guest args", argv)
	}
	if !reflect.DeepEqual(argv[sep+1:], spec.Args) {
		t.Fatalf("argv after -- = %v, want %v", argv[sep+1:], spec.Args)
	}
}
