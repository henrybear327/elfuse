// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// runSpec is the fully-resolved launch specification handed to elfuse.
type runSpec struct {
	// Args is the final command vector: resolved Entrypoint then Cmd.
	Args []string
	// Env is the final environment; bare KEY entries are already expanded
	// against the host environ, so elfuse receives only KEY=VAL entries.
	Env []string
	// Workdir is guest-absolute.
	Workdir string
	UID     uint32
	GID     uint32
}

// defaultGuestPath is Docker's conventional default PATH. run launches
// elfuse with --clear-env, so a merge yielding no PATH would leave the
// guest with no search path at all.
const defaultGuestPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// runFlags are the run-specific flags parsed before the image reference.
type runFlags struct {
	entrypoint    string
	entrypointSet bool // --entrypoint given, so "" clears the image's
	env           []string
	clearEnv      bool
	user          string
	workdir       string
	rootfs        string

	plainRootfs bool // --plain-rootfs: a plain directory, not the sparsebundle
	cs          csFlags
}

// csFlags are the sparsebundle-only flags; refuseCSFlags rejects them on
// a path that cannot honor them.
type csFlags struct {
	sparseSize string // --sparse-size: virtual size at creation (default 16g)
	noClone    bool   // --no-clone: run the base tree, no per-run COW clone
	keepRootfs bool   // --keep: leave the clone for inspection
}

// set names one of the flags carrying a non-default value, or "".
func (c csFlags) set() string {
	switch {
	case c.keepRootfs:
		return "keep"
	case c.noClone:
		return "no-clone"
	case c.sparseSize != "":
		return "sparse-size"
	}
	return ""
}

// computeRunSpec resolves Entrypoint/Cmd/Env/WorkingDir/User with
// Docker's precedence (docs/oci-images.md "Runtime Configuration"); the
// flag-only rules were checked by validateRunFlags before any network
// work.
func computeRunSpec(cfg ocispec.Image, rf runFlags, rootfs string, tail []string) (*runSpec, error) {
	args := resolveArgs(cfg.Config.Entrypoint, cfg.Config.Cmd, rf.entrypoint, rf.entrypointSet, tail)
	if len(args) == 0 {
		return nil, fmt.Errorf("no command: image has no Entrypoint/Cmd and none given")
	}

	env := resolveEnv(cfg.Config.Env, rf.env, rf.clearEnv)
	if !slices.ContainsFunc(env, func(kv string) bool {
		return strings.HasPrefix(kv, "PATH=")
	}) {
		env = append(env, "PATH="+defaultGuestPath)
	}

	workdir := rf.workdir
	if workdir == "" {
		workdir = cfg.Config.WorkingDir
	}
	if workdir == "" {
		workdir = "/"
	}
	if err := guestAbs(workdir); err != nil {
		return nil, err
	}
	// Clean folds "//" and clamps "/.." at "/", matching the guest path
	// resolver's clamp (src/syscall/path.c).
	workdir = filepath.Clean(workdir)

	// Docker resolves a slash-containing relative command against the
	// working directory and a bare name against PATH; elfuse loads the
	// initial ELF before its chdir and does no PATH lookup.
	switch {
	case filepath.IsAbs(args[0]):
	case strings.Contains(args[0], "/"):
		args[0] = filepath.Join(workdir, args[0])
	default:
		resolved, err := lookPathInRootfs(rootfs, envValue(env, "PATH"), workdir, args[0])
		if err != nil {
			return nil, err
		}
		args[0] = resolved
	}

	user := rf.user
	if user == "" {
		user = cfg.Config.User
	}
	uid, gid, err := resolveUser(rootfs, user)
	if err != nil {
		return nil, err
	}

	return &runSpec{
		Args:    args,
		Env:     env,
		Workdir: workdir,
		UID:     uid,
		GID:     gid,
	}, nil
}

// validateRunFlags checks the rules decidable from the flags alone. An
// empty --env name is what guest_env_build (src/core/guest-env.c)
// rejects; image-carried empty keys stay droppable in resolveEnv.
func validateRunFlags(rf runFlags) error {
	for _, e := range rf.env {
		if k, _, _ := strings.Cut(e, "="); k == "" {
			return fmt.Errorf("invalid --env %q: empty variable name", e)
		}
	}
	if rf.workdir != "" {
		if err := guestAbs(rf.workdir); err != nil {
			return err
		}
	}
	// hdiutil's size grammar, checked here rather than by hdiutil create
	// after the pull.
	if s := rf.cs.sparseSize; s != "" && !sparseSizeRe.MatchString(s) {
		return fmt.Errorf("invalid --sparse-size %q: want a number with an optional b|k|m|g|t|p|e suffix", s)
	}
	return nil
}

var sparseSizeRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?[bkmgtpe]?$`)

func guestAbs(workdir string) error {
	if !filepath.IsAbs(workdir) {
		return fmt.Errorf("workdir %q is not guest-absolute", workdir)
	}
	return nil
}

// resolveArgs implements Docker's Entrypoint/Cmd precedence; an empty
// --entrypoint clears the image's, so the tail or the image Cmd runs
// alone.
func resolveArgs(imgEntry, imgCmd []string, cliEntry string, entrySet bool, tail []string) []string {
	if entrySet {
		imgEntry = nil
		if cliEntry != "" {
			imgEntry, imgCmd = []string{cliEntry}, nil
		}
	}
	if len(tail) > 0 {
		return slices.Concat(imgEntry, tail)
	}
	return slices.Concat(imgEntry, imgCmd)
}

// resolveEnv mirrors the merge rules of guest_env_build
// (src/core/guest-env.c), except that a duplicate key in the base vector
// takes the last value here and the first there; a rule changed here must
// change there too.
func resolveEnv(imgEnv []string, overrides []string, clearEnv bool) []string {
	var out []string
	seen := map[string]int{}
	set := func(k, v string) {
		if idx, ok := seen[k]; ok {
			out[idx] = k + "=" + v
			return
		}
		seen[k] = len(out)
		out = append(out, k+"="+v)
	}
	if !clearEnv {
		for _, kv := range imgEnv {
			// An image-carried "=VAL" is dropped: elfuse rejects the empty
			// name, and Docker starts such an image anyway.
			if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
				set(k, v)
			}
		}
	}
	for _, e := range overrides {
		if k, v, ok := strings.Cut(e, "="); ok {
			set(k, v)
			continue
		}
		if v, ok := os.LookupEnv(e); ok {
			set(e, v)
		}
	}
	return out
}

// resolveUser resolves "uid[:gid]" and "name[:group]" against the rootfs
// /etc/passwd and /etc/group; a bare numeric uid defaults gid to uid
// (elfuse's --user convention).
func resolveUser(rootfs, spec string) (uint32, uint32, error) {
	if spec == "" {
		return 0, 0, nil
	}
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")
	// Docker refuses both halves empty around a separator; accepting them
	// would read "1000:" as a gid and look "" up in /etc/passwd.
	if userPart == "" || (hasGroup && groupPart == "") {
		return 0, 0, fmt.Errorf("invalid user %q: want UID[:GID]", spec)
	}

	uid, puidGid, err := resolveUserPart(rootfs, userPart)
	if err != nil {
		// root falls back to 0:0 only for the FROM scratch shape (no passwd
		// file or entry); a malformed root line must surface.
		if userPart != "root" || !errors.Is(err, errNoDBEntry) {
			return 0, 0, err
		}
		uid, puidGid = 0, 0
	}
	var gid uint32
	switch {
	case groupPart == "":
		gid = puidGid // passwd gid, or == uid for bare numeric
	case isAllDigits(groupPart):
		g, err := strconv.ParseUint(groupPart, 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid gid %q: %w", groupPart, err)
		}
		gid = uint32(g)
	default:
		g, err := lookupGroup(rootfs, groupPart)
		if err != nil {
			return 0, 0, err
		}
		gid = g
	}
	return uid, gid, nil
}

// resolveUserPart resolves the user component to (uid, default gid): the
// uid itself for a numeric uid, the passwd gid field for a name.
func resolveUserPart(rootfs, part string) (uint32, uint32, error) {
	if isAllDigits(part) {
		u, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid uid %q: %w", part, err)
		}
		uid := uint32(u)
		return uid, uid, nil
	}
	return lookupPasswd(rootfs, part)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// envValue returns key's value in a resolved (deduplicated) environment,
// or "" when absent.
func envValue(env []string, key string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v
		}
	}
	return ""
}

// As in exec.LookPath and runc, an empty PATH element names the working
// directory and a relative one resolves against it.
func lookPathInRootfs(rootfs, pathList, workdir, name string) (string, error) {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return "", err
	}
	defer root.Close()
	for dir := range strings.SplitSeq(pathList, ":") {
		if dir == "" {
			dir = workdir
		} else if !filepath.IsAbs(dir) {
			dir = filepath.Join(workdir, dir)
		}
		guest := filepath.Join(dir, name)
		st, err := root.Stat(strings.TrimPrefix(guest, "/"))
		if err != nil || !st.Mode().IsRegular() || st.Mode()&0o111 == 0 {
			continue
		}
		return guest, nil
	}
	return "", fmt.Errorf("%q: executable file not found in image PATH", name)
}

// openInRootfs opens a rootfs-relative path through os.Root, so an image
// symlink (etc/passwd -> /etc/passwd) cannot redirect the read to the
// host; the file stays valid after the root handle closes.
func openInRootfs(rootfs, name string) (*os.File, error) {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Open(name)
}

// errNoDBEntry marks the entry-simply-absent case (including a missing
// database file), as opposed to parse and IO failures.
var errNoDBEntry = fmt.Errorf("no such entry")

// findColonEntry returns the fields of the first line of <rootfs>/<file>
// whose first field is name and which has at least minFields fields.
// Errors name the file guest-absolute.
func findColonEntry(rootfs, file, name string, minFields int) ([]string, error) {
	f, err := openInRootfs(rootfs, file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("open /%s: %w: %w", file, errNoDBEntry, err)
		}
		return nil, fmt.Errorf("open /%s: %w", file, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// Real group lines outgrow the default 64KB token cap; allow 1MiB.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) >= minFields && fields[0] == name {
			return fields, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan /%s: %w", file, err)
	}
	return nil, fmt.Errorf("%w in /%s", errNoDBEntry, file)
}

func lookupPasswd(rootfs, name string) (uint32, uint32, error) {
	fields, err := findColonEntry(rootfs, "etc/passwd", name, 4)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve user %q: %w", name, err)
	}
	uid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve user %q: bad uid in /etc/passwd: %w", name, err)
	}
	gid, err := strconv.ParseUint(fields[3], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve user %q: bad gid in /etc/passwd: %w", name, err)
	}
	return uint32(uid), uint32(gid), nil
}

func lookupGroup(rootfs, name string) (uint32, error) {
	fields, err := findColonEntry(rootfs, "etc/group", name, 3)
	if err != nil {
		return 0, fmt.Errorf("resolve group %q: %w", name, err)
	}
	gid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("resolve group %q: bad gid in /etc/group: %w", name, err)
	}
	return uint32(gid), nil
}
