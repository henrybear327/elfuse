// Advisory flock primitive
//
// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

// One flock discipline for the whole package: every advisory lock, the
// store-level .lock among them, acquires through acquireFlock, which
// retries EINTR. Which lock guards what, and in which order, is each
// consumer's contract.

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// flockFile is an open file holding (or having held) an advisory flock.
type flockFile struct {
	f *os.File
}

// acquireFlock opens path (creating it if absent) and takes an exclusive
// flock on it, blocking until the lock is granted.
func acquireFlock(path string) (*flockFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := flockRetryIntr(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return &flockFile{f: f}, nil
}

// flockRetryIntr issues flock, retrying on EINTR (the Go runtime's
// preemption signals can interrupt a blocking acquisition).
func flockRetryIntr(fd, how int) error {
	for {
		err := syscall.Flock(fd, how)
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

// Close releases the lock and closes the file. Safe on nil and after a prior
// Close.
func (l *flockFile) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	err := l.f.Close()
	l.f = nil
	return err
}
