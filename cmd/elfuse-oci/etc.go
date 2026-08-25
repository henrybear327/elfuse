// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

var (
	hostnameForRuntime   = os.Hostname
	readHostResolvConfig = func() ([]byte, error) { return os.ReadFile("/etc/resolv.conf") }
)

// injectRuntimeFiles writes the host's /etc/{resolv.conf,hosts,hostname}
// into sysroot: elfuse does no network namespacing, so the image's stub
// resolver would otherwise win. They are runtime state, not image content,
// so overwriting a shared unpacked cache is correct.
func injectRuntimeFiles(sysroot string) error {
	// os.Root confines every write against image-controlled symlinks.
	root, err := os.OpenRoot(sysroot)
	if err != nil {
		return err
	}
	defer root.Close()

	// Guard /etc up front, or a non-directory surfaces as an opaque error
	// from the first write.
	if li, err := root.Lstat("etc"); err == nil {
		switch {
		case li.Mode()&os.ModeSymlink != 0:
			// Followed, confined, as runc and Docker do. os.Root refuses an
			// absolute target outright, wherever it points; this tool's own
			// unpack rewrites those relative.
			fi, statErr := root.Stat("etc")
			if statErr != nil {
				return fmt.Errorf("rootfs /etc is a symlink that does not resolve: %w", statErr)
			}
			if !fi.IsDir() {
				return fmt.Errorf("rootfs /etc resolves to a %s, want a directory", fi.Mode().Type())
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

	if err := replaceFile(root, "etc/hostname", []byte(host+"\n")); err != nil {
		return err
	}

	// The minimal map image runtimes write.
	hosts := "127.0.0.1\tlocalhost " + host + "\n::1\tlocalhost ip6-localhost\n"
	if err := replaceFile(root, "etc/hosts", []byte(hosts)); err != nil {
		return err
	}

	// The host's resolv.conf verbatim, with a fallback when it is absent
	// or empty.
	resolv, err := readHostResolvConfig()
	if err != nil || len(resolv) == 0 {
		resolv = []byte("nameserver 8.8.8.8\n")
	}
	return replaceFile(root, "etc/resolv.conf", resolv)
}

// prepareRootfsForRun holds every per-run rootfs mutation, so a new step
// cannot land in one launch path and miss the other.
func prepareRootfsForRun(sysroot string, spec *runSpec) error {
	if err := injectRuntimeFiles(sysroot); err != nil {
		return err
	}
	if err := ensureWorkdir(sysroot, spec.Workdir); err != nil {
		return fmt.Errorf("create workdir %s: %w", spec.Workdir, err)
	}
	return nil
}

// ensureWorkdir creates a WorkingDir no layer shipped, as Docker's runtime
// does at container start; an existing non-directory fails here rather
// than at elfuse's chdir.
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
	st, err := root.Stat(rel)
	if err == nil {
		if !st.IsDir() {
			return &fs.PathError{
				Op:   "mkdir",
				Path: workdir,
				Err:  syscall.ENOTDIR,
			}
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return root.MkdirAll(rel, 0o755)
}
