// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// A trimmed capture of real hdiutil attach -plist output.
const attachPlistFixture = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>system-entities</key>
	<array>
		<dict>
			<key>dev-entry</key>
			<string>/dev/disk3s1</string>
			<key>mount-point</key>
			<string>/Volumes/elfuse_sysroot</string>
		</dict>
	</array>
</dict>
</plist>`

func TestParseMountpoint(t *testing.T) {
	got, err := parseMountpoint([]byte(attachPlistFixture))
	if err != nil || got != "/Volumes/elfuse_sysroot" {
		t.Fatalf("fixture parse = %q, %v", got, err)
	}
	got, err = parseMountpoint([]byte(`<plist version="1.0"><dict>
		<key>system-entities</key><array><dict>
		<key>mount-point</key><string>/tmp/a &amp; b&#39;s mnt</string>
		</dict></array></dict></plist>`))
	if err != nil || got != "/tmp/a & b's mnt" {
		t.Fatalf("entity decode = %q, %v", got, err)
	}
	if _, err := parseMountpoint([]byte("<plist></plist>")); err == nil {
		t.Fatal("missing mount-point must error, not return \"\"")
	}
	if _, err := parseMountpoint([]byte("garbage")); err == nil {
		t.Fatal("a non-plist answer must error")
	}
}

// installFakeHdiutil puts an hdiutil stub first on PATH that logs each
// invocation, answers attach with $ELFUSE_TEST_HDIUTIL_ATTACH or a plist
// naming the requested mountpoint (so provision proceeds against a plain
// directory), and answers info with $ELFUSE_TEST_HDIUTIL_INFO or an
// empty images list.
func installFakeHdiutil(t *testing.T) (logPath string) {
	t.Helper()
	logPath = filepath.Join(t.TempDir(), "hdiutil.log")
	stub := `echo "$@" >> "` + logPath + `"
case "$1" in
attach)
  if [ -n "$ELFUSE_TEST_HDIUTIL_ATTACH" ]; then cat "$ELFUSE_TEST_HDIUTIL_ATTACH"; exit 0; fi
  mnt=""
  prev=""
  for a in "$@"; do
    [ "$prev" = "-mountpoint" ] && mnt="$a"
    prev="$a"
  done
  # The real hdiutil reports the canonical path (/private/var for /var).
  [ -n "$ELFUSE_TEST_HDIUTIL_ATTACH_CANONICAL" ] && mnt=$(cd "$mnt" && pwd -P)
  printf '<plist version="1.0"><dict><key>system-entities</key><array><dict><key>mount-point</key><string>%s</string></dict></array></dict></plist>\n' "$mnt"
  ;;
create)
  # The image path is the last argument; a real create makes a bundle
  # directory there, a failed one may leave it behind.
  for a in "$@"; do last="$a"; done
  mkdir -p "$last"
  [ -n "$ELFUSE_TEST_HDIUTIL_CREATE_FAIL" ] && exit 1
  ;;
detach)
  [ -n "$ELFUSE_TEST_HDIUTIL_DETACH_FAIL" ] && { echo "busy" >&2; exit 1; }
  ;;
info)
  if [ -n "$ELFUSE_TEST_HDIUTIL_INFO" ]; then cat "$ELFUSE_TEST_HDIUTIL_INFO"
  else printf '<plist version="1.0"><dict><key>images</key><array/></dict></plist>\n'; fi
  ;;
esac
exit 0
`
	prependPath(t, filepath.Dir(writeShellStub(t, "hdiutil", stub)))
	return logPath
}

// fakeAttachedInfo makes the stub's info answer list image mounted at
// mount, as a warm slot's probe expects.
func fakeAttachedInfo(t *testing.T, image, mount string) {
	t.Helper()
	body := `<plist version="1.0"><dict><key>images</key><array><dict><key>image-path</key><string>` + image +
		`</string><key>system-entities</key><array><dict><key>mount-point</key><string>` + mount +
		`</string></dict></array></dict></array></dict></plist>`
	path := filepath.Join(t.TempDir(), "info.plist")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELFUSE_TEST_HDIUTIL_INFO", path)
}

func TestProvisionCreatesAttachesAndReuses(t *testing.T) {
	log := installFakeHdiutil(t)
	bundle := filepath.Join(t.TempDir(), "bundle")
	mount, err := provisionCaseSensitive(bundle, "")
	if err != nil {
		t.Fatal(err)
	}
	if mount != filepath.Join(bundle, "mnt") {
		t.Fatalf("mount = %q", mount)
	}
	b, _ := os.ReadFile(log)
	mustContain(t, string(b), "create", "Case-sensitive APFS", "16g", "SPARSEBUNDLE", "elfuse_sysroot", "attach", "-nobrowse", "-plist")
	if _, err := os.Stat(filepath.Join(mount, ".metadata_never_index")); err != nil {
		t.Fatalf("spotlight marker: %v", err)
	}

	// Warm bundle: create must not run again; a live mount of this slot's
	// own bundle skips attach.
	os.WriteFile(log, nil, 0o644)
	old := isMountPointFn
	isMountPointFn = func(string) bool { return true }
	t.Cleanup(func() { isMountPointFn = old })
	fakeAttachedInfo(t, csBundleImage(bundle), mount)
	if _, err := provisionCaseSensitive(bundle, ""); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(log)
	if strings.Contains(string(b), "create") || strings.Contains(string(b), "attach") {
		t.Fatalf("warm provision must reuse, ran: %s", b)
	}
}

// attach succeeded, so a failure after it must detach what it mounted.
func TestProvisionDetachesOnUnparsableAttach(t *testing.T) {
	log := installFakeHdiutil(t)
	bad := filepath.Join(t.TempDir(), "attach.out")
	if err := os.WriteFile(bad, []byte("not a plist\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELFUSE_TEST_HDIUTIL_ATTACH", bad)
	bundle := filepath.Join(t.TempDir(), "bundle")
	if _, err := provisionCaseSensitive(bundle, ""); err == nil {
		t.Fatal("provision succeeded on an unparsable attach answer")
	}
	b, _ := os.ReadFile(log)
	want := "detach " + filepath.Join(bundle, "mnt") + " -force\n"
	if !strings.HasSuffix(string(b), want) {
		t.Fatalf("hdiutil log must end with %q, got:\n%s", want, b)
	}
}

// The canonical spelling hdiutil reports for a /var path is the same
// mount; the slot's own spelling is what provision returns.
func TestProvisionAcceptsCanonicalMountpoint(t *testing.T) {
	installFakeHdiutil(t)
	t.Setenv("ELFUSE_TEST_HDIUTIL_ATTACH_CANONICAL", "1")
	bundle := filepath.Join(t.TempDir(), "bundle")
	canonical, err := filepath.EvalSymlinks(filepath.Dir(bundle))
	if err != nil {
		t.Fatal(err)
	}
	if canonical == filepath.Dir(bundle) {
		t.Skip("TempDir has no symlinked prefix on this host")
	}
	mount, err := provisionCaseSensitive(bundle, "")
	if err != nil {
		t.Fatal(err)
	}
	if mount != filepath.Join(bundle, "mnt") {
		t.Fatalf("mount = %q, want the slot's spelling", mount)
	}
}

// A warm probe reuses a mount only when hdiutil says it is this slot's
// bundle; a foreign volume at the path is refused untouched.
func TestProvisionRefusesForeignWarmMount(t *testing.T) {
	log := installFakeHdiutil(t)
	bundle := filepath.Join(t.TempDir(), "bundle")
	mnt := csMountPath(bundle)
	os.MkdirAll(mnt, 0o755)
	old := isMountPointFn
	isMountPointFn = func(string) bool { return true }
	t.Cleanup(func() { isMountPointFn = old })
	fakeAttachedInfo(t, filepath.Join(t.TempDir(), "other.sparsebundle"), mnt)
	_, err := provisionCaseSensitive(bundle, "")
	if err == nil || !strings.Contains(err.Error(), "not from") {
		t.Fatalf("err = %v, want a foreign-mount refusal", err)
	}
	if b, _ := os.ReadFile(log); strings.Contains(string(b), "attach") || strings.Contains(string(b), "detach") {
		t.Fatalf("foreign mount must be left alone, ran:\n%s", b)
	}
}

// hdiutil honoring -mountpoint elsewhere would leave a mount no later
// probe finds: refuse it, and detach what was mounted.
func TestProvisionRefusesForeignMountpoint(t *testing.T) {
	log := installFakeHdiutil(t)
	other := filepath.Join(t.TempDir(), "elsewhere")
	plist := filepath.Join(t.TempDir(), "attach.out")
	body := `<plist version="1.0"><dict><key>system-entities</key><array><dict><key>mount-point</key><string>` + other + `</string></dict></array></dict></plist>`
	if err := os.WriteFile(plist, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELFUSE_TEST_HDIUTIL_ATTACH", plist)
	bundle := filepath.Join(t.TempDir(), "bundle")
	_, err := provisionCaseSensitive(bundle, "")
	if err == nil || !strings.Contains(err.Error(), other) || !strings.Contains(err.Error(), filepath.Join(bundle, "mnt")) {
		t.Fatalf("err = %v, want both paths named", err)
	}
	b, _ := os.ReadFile(log)
	if want := "detach " + other + " -force\n"; !strings.HasSuffix(string(b), want) {
		t.Fatalf("hdiutil log must end with %q, got:\n%s", want, b)
	}
}

// A detach that fails after a failed provision is reported, not dropped.
func TestProvisionReportsFailedDetach(t *testing.T) {
	installFakeHdiutil(t)
	bad := filepath.Join(t.TempDir(), "attach.out")
	if err := os.WriteFile(bad, []byte("not a plist\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELFUSE_TEST_HDIUTIL_ATTACH", bad)
	t.Setenv("ELFUSE_TEST_HDIUTIL_DETACH_FAIL", "1")
	_, err := provisionCaseSensitive(filepath.Join(t.TempDir(), "bundle"), "")
	if err == nil || !strings.Contains(err.Error(), "detach") || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("err = %v, want the detach failure joined", err)
	}
}

// A failed create must not leave a partial bundle for the next run to
// mistake for a whole one.
func TestEnsureBundleImageRemovesPartialCreate(t *testing.T) {
	installFakeHdiutil(t)
	t.Setenv("ELFUSE_TEST_HDIUTIL_CREATE_FAIL", "1")
	image := csBundleImage(t.TempDir())
	if err := ensureBundleImage(image, ""); err == nil {
		t.Fatal("failed create must error")
	}
	if _, err := os.Lstat(image); !os.IsNotExist(err) {
		t.Fatalf("partial bundle left behind: %v", err)
	}
}

func TestProvisionRejectsSymlinkedBundle(t *testing.T) {
	installFakeHdiutil(t)
	bundle := t.TempDir()
	if err := os.Symlink(t.TempDir(), csBundleImage(bundle)); err != nil {
		t.Fatal(err)
	}
	_, err := provisionCaseSensitive(bundle, "")
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v", err)
	}
}

func TestProvisionRejectsSymlinkedMount(t *testing.T) {
	installFakeHdiutil(t)
	bundle := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(bundle, "mnt")); err != nil {
		t.Fatal(err)
	}
	_, err := provisionCaseSensitive(bundle, "")
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v", err)
	}
}

// runCS runs the sparsebundle path and returns the guest exit status it
// carries out as an error.
func runCS(t *testing.T, rc *runContext) int {
	t.Helper()
	var code exitStatus
	if err := runCaseSensitive(context.Background(), rc); !errors.As(err, &code) {
		t.Fatalf("run returned %v instead of an exit status", err)
	}
	return int(code)
}

type csSeam struct {
	spawned string
	code    int
}

// seamCSRun records the spawn instead of launching a binary.
func seamCSRun(t *testing.T) *csSeam {
	t.Helper()
	got := &csSeam{}
	old := spawnForRun
	spawnForRun = func(bin, rootfs string, spec *runSpec) (int, error) {
		got.spawned = rootfs
		return got.code, nil
	}
	t.Cleanup(func() { spawnForRun = old })
	return got
}

func csTestContext(t *testing.T) *runContext {
	t.Helper()
	s, d := storeWithImage(t, "cs:1", testImage{
		config: ocispec.ImageConfig{Entrypoint: []string{"/bin/app"}},
		layers: [][]tarEntry{{{Name: "bin/"}, {Name: "bin/app", Body: "x", Mode: 0o755}}},
	})
	m := manifestOf(t, s, d)
	_, cfg, err := s.configFor(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	return &runContext{s: s, ref: "cs:1", digest: d, m: m, cfg: cfg}
}

func TestRunCaseSensitiveHappyPath(t *testing.T) {
	installFakeHdiutil(t)
	rc := csTestContext(t)
	got := seamCSRun(t)
	got.code = 7

	var code int
	captureOutput(t, func() { code = runCS(t, rc) })
	if code != 7 {
		t.Fatalf("guest exit = %d, want 7", code)
	}
	bundle, _ := rc.s.cacheDir(cacheCS, rc.digest)
	mount := csMountPath(bundle)
	// The guest ran out of a per-run clone, not the base tree.
	if got.spawned == filepath.Join(mount, "rootfs") || !strings.HasPrefix(filepath.Base(got.spawned), "run-") {
		t.Fatalf("spawned rootfs = %q, want a run-* clone", got.spawned)
	}
	// Base tree unpacked once; clone removed after exit.
	if _, err := os.Stat(filepath.Join(mount, "rootfs", "bin", "app")); err != nil {
		t.Fatalf("base tree: %v", err)
	}
	if _, err := os.Stat(got.spawned); !os.IsNotExist(err) {
		t.Fatalf("clone must be removed after the run: %v", err)
	}
}

func TestRunCaseSensitiveNoCloneAndKeep(t *testing.T) {
	installFakeHdiutil(t)
	rc := csTestContext(t)
	got := seamCSRun(t)

	// --no-clone runs the base tree itself.
	rc.rf.cs.noClone = true
	captureOutput(t, func() { runCS(t, rc) })
	bundle, _ := rc.s.cacheDir(cacheCS, rc.digest)
	if got.spawned != csBaseTree(csMountPath(bundle)) {
		t.Fatalf("no-clone spawned = %q", got.spawned)
	}

	// --keep leaves the clone and says where everything is.
	rc.rf.cs.noClone = false
	rc.rf.cs.keepRootfs = true
	_, stderr := captureOutput(t, func() { runCS(t, rc) })
	mustContain(t, stderr, "kept clone: "+got.spawned, "mount stays attached")
	if _, err := os.Stat(got.spawned); err != nil {
		t.Fatalf("kept clone must survive: %v", err)
	}
}

// Provisioning waits for the store lock, so a second cold run cannot
// clear the mount path under the first one's attach.
func TestRunCaseSensitiveProvisionsUnderStoreLock(t *testing.T) {
	log := installFakeHdiutil(t)
	rc := csTestContext(t)
	seamCSRun(t)
	held, err := acquireFlock(context.Background(), rc.s.lockPath())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*flockPoll)
	defer cancel()
	err = runCaseSensitive(ctx, rc)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run under a held lock returned %v, want the deadline", err)
	}
	if b, _ := os.ReadFile(log); len(b) != 0 {
		t.Fatalf("hdiutil ran without the lock:\n%s", b)
	}
}

func TestRunCaseSensitiveWarmBundleReused(t *testing.T) {
	installFakeHdiutil(t)
	rc := csTestContext(t)
	seamCSRun(t)

	captureOutput(t, func() { runCS(t, rc) })
	bundle, _ := rc.s.cacheDir(cacheCS, rc.digest)
	marker := filepath.Join(csBaseTree(csMountPath(bundle)), "warm")
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// Model the volume still attached: provision must reuse it untouched
	// (a real detached bundle keeps its tree inside the volume, not in
	// the mnt dir this test uses).
	old := isMountPointFn
	isMountPointFn = func(string) bool { return true }
	t.Cleanup(func() { isMountPointFn = old })
	fakeAttachedInfo(t, csBundleImage(bundle), csMountPath(bundle))
	_, stderr := captureOutput(t, func() { runCS(t, rc) })
	if strings.Contains(stderr, "Unpacking") {
		t.Fatalf("warm bundle re-unpacked:\n%s", stderr)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("warm base tree was replaced")
	}
}

// The darwin default is the sparsebundle path, and the guest's status
// reaches main as an exitStatus.
func TestCmdRunDefaultDispatchesToSparsebundle(t *testing.T) {
	installFakeHdiutil(t)
	writeElfuseStub(t, "exit 0")
	rc := csTestContext(t)
	got := seamCSRun(t)
	got.code = 3
	var err error
	captureOutput(t, func() { err = cmdRun([]string{"--store", rc.s.root, "cs:1"}) })
	var code exitStatus
	if !errors.As(err, &code) || code != 3 {
		t.Fatalf("cmdRun = %v, want exit status 3", err)
	}
	if !strings.Contains(got.spawned, filepath.Join("cs", "sha256")) {
		t.Fatalf("default run used %q, not the sparsebundle path", got.spawned)
	}
}

func TestCmdRunRefusesSparseFlagsOnPlainPath(t *testing.T) {
	s := tempStore(t)
	for _, args := range [][]string{
		{"--store", s.root, "--plain-rootfs", "--keep", "x:1"},
		{"--store", s.root, "--rootfs", t.TempDir(), "--no-clone", "x:1"},
		{"--store", s.root, "--plain-rootfs", "--sparse-size", "1g", "x:1"},
	} {
		var err error
		captureOutput(t, func() { err = cmdRun(args) })
		if err == nil || !strings.Contains(err.Error(), "sparsebundle path") {
			t.Errorf("args %v: err = %v", args, err)
		}
	}
}

// --keep preserves the clone on the failure exits too.
func TestRunCaseSensitiveKeepSurvivesLaunchFailure(t *testing.T) {
	installFakeHdiutil(t)
	rc := csTestContext(t)
	rc.rf.cs.keepRootfs = true
	old := spawnForRun
	spawnForRun = func(bin, rootfs string, spec *runSpec) (int, error) {
		return 0, fmt.Errorf("launch failed")
	}
	t.Cleanup(func() { spawnForRun = old })

	var err error
	var stderr string
	_, stderr = captureOutput(t, func() {
		err = runCaseSensitive(context.Background(), rc)
	})
	if err == nil {
		t.Fatal("spawn failure must surface")
	}
	mustContain(t, stderr, "kept clone: ")
	bundle, _ := rc.s.cacheDir(cacheCS, rc.digest)
	entries, readErr := os.ReadDir(csMountPath(bundle))
	if readErr != nil {
		t.Fatal(readErr)
	}
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "run-") {
			found = true
		}
	}
	if !found {
		t.Fatal("clone must survive a failed launch under --keep")
	}
}

// An explicit --sparse-size against an existing image is inert and says
// so.
func TestSparseSizeIgnoredOnWarmBundleIsReported(t *testing.T) {
	installFakeHdiutil(t)
	bundle := filepath.Join(t.TempDir(), "bundle")
	if _, err := provisionCaseSensitive(bundle, ""); err != nil {
		t.Fatal(err)
	}
	var err error
	_, stderr := captureOutput(t, func() {
		_, err = provisionCaseSensitive(bundle, "64g")
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, stderr, "--sparse-size ignored")
}

// clean force-detaches a still mounted bundle volume before removing
// its directory.
func TestCleanDetachesMountedBundle(t *testing.T) {
	log := installFakeHdiutil(t)
	s := tempStore(t)
	mnt := filepath.Join(s.root, "cs", "sha256", strings.Repeat("c", 64), "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	old := isMountPointFn
	isMountPointFn = func(p string) bool { return p == mnt }
	t.Cleanup(func() { isMountPointFn = old })

	var err error
	captureOutput(t, func() { err = cmdClean([]string{"--store", s.root, "--cache"}) })
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	mustContain(t, string(b), "detach", "-force", mnt)
	if _, err := os.Lstat(filepath.Join(s.root, "cs")); !os.IsNotExist(err) {
		t.Fatal("cs/ must be removed")
	}
}

// A trimmed capture of real hdiutil info -plist output: two store
// bundles attached, one listing an extra entity with no mount point and
// one at a path with an escaped &, plus a foreign image.
var infoPlistFixture = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>images</key>
	<array>
		<dict>
			<key>image-path</key>
			<string>/Volumes/Other/scratch.dmg</string>
			<key>system-entities</key>
			<array>
				<dict>
					<key>dev-entry</key>
					<string>/dev/disk2s1</string>
					<key>mount-point</key>
					<string>/Volumes/scratch</string>
				</dict>
			</array>
		</dict>
		<dict>
			<key>image-path</key>
			<string>/tmp/gone/cs/sha256/` + strings.Repeat("a", 64) + `/rootfs.sparsebundle</string>
			<key>image-type</key>
			<string>sparse bundle disk image</string>
			<key>system-entities</key>
			<array>
				<dict>
					<key>content-hint</key>
					<string>GUID_partition_scheme</string>
					<key>dev-entry</key>
					<string>/dev/disk4</string>
				</dict>
				<dict>
					<key>dev-entry</key>
					<string>/dev/disk5s1</string>
					<key>mount-point</key>
					<string>/tmp/gone/cs/sha256/` + strings.Repeat("a", 64) + `/mnt</string>
				</dict>
			</array>
		</dict>
		<dict>
			<key>image-path</key>
			<string>/tmp/a&amp;b/cs/sha256/` + strings.Repeat("b", 64) + `/rootfs.sparsebundle</string>
			<key>system-entities</key>
			<array>
				<dict>
					<key>dev-entry</key>
					<string>/dev/disk7s1</string>
					<key>mount-point</key>
					<string>/tmp/a&amp;b/cs/sha256/` + strings.Repeat("b", 64) + `/mnt</string>
				</dict>
			</array>
		</dict>
	</array>
</dict>
</plist>
`

func TestParseAttachedBundlesKeepsStoreBundlesOnly(t *testing.T) {
	got, err := parseAttachedBundles([]byte(infoPlistFixture), isStoreBundlePath)
	if err != nil {
		t.Fatal(err)
	}
	want := []bundleMount{
		{image: "/tmp/gone/cs/sha256/" + strings.Repeat("a", 64) + "/rootfs.sparsebundle",
			mount: "/tmp/gone/cs/sha256/" + strings.Repeat("a", 64) + "/mnt"},
		{image: "/tmp/a&b/cs/sha256/" + strings.Repeat("b", 64) + "/rootfs.sparsebundle",
			mount: "/tmp/a&b/cs/sha256/" + strings.Repeat("b", 64) + "/mnt"},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	got, err = parseAttachedBundles([]byte(`<plist version="1.0"><dict><key>images</key><array/></dict></plist>`), isStoreBundlePath)
	if err != nil || got != nil {
		t.Fatalf("empty images list = %+v, %v; must parse to nothing", got, err)
	}
}

// writeInfoFixture points the stub's info verb at a plist in which the
// digest-a bundle sits under a directory that does not exist and the
// digest-b bundle under root, which does.
func writeInfoFixture(t *testing.T, root string) {
	t.Helper()
	plist := strings.ReplaceAll(infoPlistFixture, "/tmp/a&amp;b", root)
	if err := os.MkdirAll(filepath.Join(root, "cs", "sha256", strings.Repeat("b", 64), "rootfs.sparsebundle"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "info.plist")
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELFUSE_TEST_HDIUTIL_INFO", path)
}

func TestDetachOrphanBundlesSkipsLiveStores(t *testing.T) {
	log := installFakeHdiutil(t)
	writeInfoFixture(t, t.TempDir())
	n, err := detachOrphanBundles()
	if err != nil || n != 1 {
		t.Fatalf("n, err = %d, %v", n, err)
	}
	b, _ := os.ReadFile(log)
	mustContain(t, string(b), "detach /tmp/gone/cs/sha256/"+strings.Repeat("a", 64)+"/mnt -force")
	if strings.Contains(string(b), strings.Repeat("b", 64)) {
		t.Fatalf("a bundle whose store exists was detached:\n%s", b)
	}
}

// The sweep does not hang off the store: a missing store still detaches
// the orphan.
func TestCleanSweepsOrphansEvenWithoutStore(t *testing.T) {
	log := installFakeHdiutil(t)
	writeInfoFixture(t, t.TempDir())
	var err error
	_, stderr := captureOutput(t, func() {
		err = cmdClean([]string{"--store", filepath.Join(t.TempDir(), "never")})
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, stderr, "Nothing to clean", "Detached 1 orphaned")
	b, _ := os.ReadFile(log)
	mustContain(t, string(b), "detach /tmp/gone/")
}
