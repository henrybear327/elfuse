// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1"
)

// runSpec is the fully-resolved launch specification handed to elfuse.
type runSpec struct {
	// Args is the final command vector: resolved Entrypoint followed by the
	// resolved Cmd (image Cmd, the CLI tail, or nothing per the precedence
	// matrix below).
	Args []string
	// Env is the final environment (image Env, overridden/appended by --env;
	// --clear-env starts from empty). Bare KEY entries are expanded against
	// the host environ here so elfuse receives only KEY=VAL.
	Env []string
	// Workdir is the guest-absolute initial working directory.
	Workdir string
	// UID/GID are the resolved numeric identity.
	UID uint32
	GID uint32
}

// defaultGuestPath is Docker's conventional default PATH. computeRunSpec
// appends it when neither the image config nor --env supplies a PATH: run
// launches elfuse with --clear-env, so a guest whose image config omits PATH
// would otherwise start with no search path at all.
const defaultGuestPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// runFlags are the run-specific flags parsed between the common flags and the
// image reference. Everything after the reference is the guest argv tail and
// is not flag-parsed.
type runFlags struct {
	entrypoint string
	env        []string
	clearEnv   bool
	user       string
	workdir    string
	rootfs     string

	// Case-sensitive sparsebundle and COW clone controls.
	plainRootfs bool   // --plain-rootfs: skip the sparsebundle, use a plain dir
	sparseSize  string // --sparse-size SIZE: sparsebundle virtual size (default 16g)
	noClone     bool   // --no-clone: run against the base tree, no COW clone
	keepRootfs  bool   // --keep: do not remove the COW clone on exit
}

// computeRunSpec applies the Entrypoint/Cmd/Env/WorkingDir/User precedence.
//
// Command (Docker/OCI semantics, matching the branch's runspec.c):
//   - --entrypoint overrides the image Entrypoint AND discards the image Cmd.
//     The CLI tail then becomes the new Cmd; with no tail the command is just
//     the --entrypoint.
//   - Without --entrypoint, a non-empty CLI tail replaces the image Cmd while
//     the image Entrypoint is kept.
//   - With neither --entrypoint nor a tail, the command is image Entrypoint +
//     image Cmd.
//
// Env:
//   - --clear-env starts from empty; otherwise the base is the image Env.
//   - --env KEY=VAL overrides any existing KEY and appends if new.
//   - --env KEY (bare) inherits KEY from the host environ (resolved here).
//   - a PATH is guaranteed: when the merged result carries none, Docker's
//     conventional default is appended (defaultGuestPath).
//
// WorkingDir: --workdir, else image WorkingDir, else "/".
// User: --user, else image User, resolved to numeric uid:gid against the
// rootfs /etc/passwd and /etc/group.
func computeRunSpec(cfg *v1.ConfigFile, rf runFlags, rootfs string, tail []string) (*runSpec, error) {
	args := resolveArgs(cfg.Config.Entrypoint, cfg.Config.Cmd, rf.entrypoint, tail)
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
	if !filepath.IsAbs(workdir) {
		return nil, fmt.Errorf("workdir %q is not guest-absolute", workdir)
	}

	// Docker resolves a relative path command (one containing a slash, like
	// "./server") against the working directory and a bare name against the
	// merged PATH. elfuse resolves the initial ELF before elfuse_launch
	// chdirs to --workdir and performs no PATH lookup, so both happen here:
	// WorkingDir /app with Entrypoint ./server must load /app/server (not
	// ./server relative to wherever the user invoked elfuse-oci), and an
	// image Cmd of ["node"] must resolve inside the rootfs via PATH.
	switch {
	case filepath.IsAbs(args[0]):
	case strings.Contains(args[0], "/"):
		args[0] = filepath.Join(workdir, args[0])
	default:
		resolved, err := lookPathInRootfs(rootfs, envValue(env, "PATH"), args[0])
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

// resolveArgs implements the Entrypoint/Cmd precedence described above.
func resolveArgs(imgEntry, imgCmd []string, cliEntry string, tail []string) []string {
	if cliEntry != "" {
		// --entrypoint clobbers image Entrypoint and image Cmd. The CLI tail,
		// if any, is the new Cmd.
		return append([]string{cliEntry}, tail...)
	}
	if len(tail) > 0 {
		// CLI args replace image Cmd, keep image Entrypoint.
		return slices.Concat(imgEntry, tail)
	}
	// No --entrypoint, no tail: image Entrypoint + image Cmd.
	return slices.Concat(imgEntry, imgCmd)
}

// resolveEnv builds the final environment list.
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
			// Drop empty-key entries ("=VAL") instead of forwarding them:
			// elfuse rejects --env with an empty variable name, and an image
			// carrying such an entry still starts under Docker.
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
		// Bare KEY: inherit from the host environ, or skip if unset.
		if v, ok := os.LookupEnv(e); ok {
			set(e, v)
		}
	}
	return out
}

// resolveUser resolves a user spec ("uid", "uid:gid", "name", "name:group")
// to numeric uid:gid against the rootfs /etc/passwd and /etc/group. A bare
// numeric uid defaults gid to uid (matching elfuse's --user convention).
// "root" resolves through /etc/passwd like any other name (its gid can
// differ from 0), but falls back to 0:0 when the rootfs has no usable
// passwd entry for it: root's uid is 0 by definition, so FROM scratch-style
// images with USER root keep working. An explicit ":group" part is still
// resolved normally.
func resolveUser(rootfs, spec string) (uint32, uint32, error) {
	if spec == "" {
		return 0, 0, nil
	}
	userPart, groupPart, _ := strings.Cut(spec, ":")

	uid, puidGid, err := resolveUserPart(rootfs, userPart)
	if err != nil {
		if userPart != "root" {
			return 0, 0, err
		}
		// No readable /etc/passwd or no root entry: uid 0 by definition,
		// gid 0 as the only sane default.
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

// resolveUserPart resolves the user component to (uid, defaultGid). For a
// numeric uid the default gid is the uid itself; for a name it is the gid
// field of the matching /etc/passwd entry.
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

// envValue returns the value of key in a resolved KEY=VALUE environment
// slice, or "" when absent. resolveEnv dedups keys, so the first match is
// the only one.
func envValue(env []string, key string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v
		}
	}
	return ""
}

// lookPathInRootfs resolves a bare command name against the merged guest PATH
// inside the image rootfs, as Docker does for exec-form commands. Candidates
// resolve through os.Root so image symlinks stay confined to the rootfs; a
// match must be a regular file with an execute bit. Relative or empty PATH
// entries are skipped: they would be cwd-relative at exec time, which the
// launcher cannot honor.
func lookPathInRootfs(rootfs, pathList, name string) (string, error) {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return "", err
	}
	defer root.Close()
	for dir := range strings.SplitSeq(pathList, ":") {
		if !filepath.IsAbs(dir) {
			continue
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

// openInRootfs opens a rootfs-relative path via os.Root so an
// image-controlled symlink (e.g. etc/passwd -> /etc/passwd) cannot redirect
// the read to host files outside the rootfs. The returned file stays valid
// after the root handle is closed.
func openInRootfs(rootfs, name string) (*os.File, error) {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Open(name)
}

// findColonEntry scans the colon-separated database <rootfs>/<file> (e.g.
// etc/passwd) for the line whose first field is name and has at least
// minFields fields, returning the fields. Errors name the file guest-absolute
// so callers only add their own context prefix.
func findColonEntry(rootfs, file, name string, minFields int) ([]string, error) {
	f, err := openInRootfs(rootfs, file)
	if err != nil {
		return nil, fmt.Errorf("open /%s: %w", file, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) >= minFields && fields[0] == name {
			return fields, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan /%s: %w", file, err)
	}
	return nil, fmt.Errorf("not found in /%s", file)
}

// lookupPasswd finds name in <rootfs>/etc/passwd, returning (uid, gid).
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

// lookupGroup finds name in <rootfs>/etc/group, returning gid.
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
