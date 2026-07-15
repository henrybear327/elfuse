// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

var (
	hostnameForRuntime   = os.Hostname
	readHostResolvConfig = func() ([]byte, error) { return os.ReadFile("/etc/resolv.conf") }
)

// injectRuntimeFiles writes host-truth /etc/{resolv.conf,hosts,hostname} into
// sysroot before elfuse launches the guest. Runtimes that consume OCI images
// synthesize these per-run rather than handing the guest the image's (often
// stub or empty) copies: the guest's resolver reads /etc/resolv.conf to find its
// nameserver, and because --sysroot redirects guest absolute paths into the
// rootfs, the guest would otherwise read the image's file, not the host's.
// elfuse does not do network namespacing (the guest uses the host network
// directly), so the host's resolver config is the correct one to hand it.
//
// Overwrite is intentional: these files are runtime-controlled, not image
// content. The caller passes the final sysroot elfuse will receive as
// --sysroot (the per-run COW clone on the case-sensitive path, or the plain
// rootfs directory on the --plain-rootfs path), so writes are isolated to
// this run except when the caller opted into mutating the base tree
// (--no-clone / --plain-rootfs).
func injectRuntimeFiles(sysroot string) error {
	// All access goes through os.Root so image-controlled symlinks (a
	// symlinked /etc directory or a symlinked target file such as
	// etc/resolv.conf -> /etc/resolv.conf) cannot redirect the writes
	// outside the rootfs.
	root, err := os.OpenRoot(sysroot)
	if err != nil {
		return err
	}
	defer root.Close()

	// Guard against a stray non-directory at /etc (e.g. a malformed image):
	// replace a symlink rather than chasing it, and reject any other
	// non-directory up front; letting it slide would only surface later as
	// an opaque "not a directory" from the first runtime-file write.
	if li, err := root.Lstat("etc"); err == nil {
		switch {
		case li.Mode()&os.ModeSymlink != 0:
			if err := root.Remove("etc"); err != nil {
				return err
			}
		case !li.IsDir():
			return fmt.Errorf("rootfs /etc is a %s, want a directory", li.Mode().Type())
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := root.Mkdir("etc", 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}

	host, err := hostnameForRuntime()
	if err != nil || host == "" {
		host = "localhost"
	}

	if err := writeRuntimeFile(root, "etc/hostname", []byte(host+"\n")); err != nil {
		return err
	}

	// Minimal hosts map: localhost + the guest's own hostname, mirroring what
	// image runtimes conventionally write.
	hosts := "127.0.0.1\tlocalhost " + host + "\n::1\tlocalhost ip6-localhost\n"
	if err := writeRuntimeFile(root, "etc/hosts", []byte(hosts)); err != nil {
		return err
	}

	// resolv.conf: copy the host's verbatim (host-truth) so the guest's DNS
	// lookups hit the same nameservers the host uses. Fall back to a minimal
	// default if the host file is absent or empty.
	resolv, err := readHostResolvConfig()
	if err != nil || len(resolv) == 0 {
		resolv = []byte("nameserver 8.8.8.8\n")
	}
	return writeRuntimeFile(root, "etc/resolv.conf", resolv)
}

// writeRuntimeFile replaces the rootfs-relative name with content. The
// content is written to a unique temp file beside name and renamed into
// place: rename replaces the existing directory entry without following it,
// so a symlink shipped by the image at that name is unlinked rather than
// chased, and a concurrent writer (two --no-clone / --plain-rootfs runs of
// the same digest share the base tree) never observes a missing or
// half-written file the way a remove-then-create sequence would expose.
func writeRuntimeFile(root *os.Root, name string, content []byte) error {
	tmp := fmt.Sprintf("%s.tmp.%d.%d", name, os.Getpid(), time.Now().UnixNano())
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		_ = root.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	return nil
}

// prepareRootfsForRun performs the per-run rootfs mutations both launch
// paths need, in one place so a new preparation step cannot land in one path
// and silently miss the other: inject the host-truth /etc files, then make
// sure the spec's working directory exists.
func prepareRootfsForRun(sysroot string, spec *runSpec) error {
	if err := injectRuntimeFiles(sysroot); err != nil {
		return err
	}
	if err := ensureWorkdir(sysroot, spec.Workdir); err != nil {
		return fmt.Errorf("create workdir %s: %w", spec.Workdir, err)
	}
	return nil
}

// ensureWorkdir creates the working directory inside the rootfs when it is
// absent. An image config may name a WorkingDir no layer ships (a config-only
// WORKDIR); Docker's runtime creates the directory at container start, so a
// run here must too rather than failing elfuse's chdir. An existing path,
// including one reached through image symlinks, is left untouched.
func ensureWorkdir(sysroot, workdir string) error {
	rel := strings.TrimPrefix(workdir, "/")
	if rel == "" {
		return nil
	}
	root, err := os.OpenRoot(sysroot)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Stat(rel); err == nil {
		return nil
	}
	return root.MkdirAll(rel, 0o755)
}
