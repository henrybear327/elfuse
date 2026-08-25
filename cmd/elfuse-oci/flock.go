// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// flockPoll is the retry interval while another process holds the lock.
const flockPoll = 50 * time.Millisecond

// flockFile is an open file holding an exclusive advisory flock.
type flockFile struct {
	f *os.File
}

// acquireFlock opens path (creating it if absent) and takes an exclusive
// flock on it, polling non-blocking until ctx ends: a blocking LOCK_EX
// would ignore the caller's deadline.
func acquireFlock(ctx context.Context, path string) (*flockFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &flockFile{f: f}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, ctx.Err())
		case <-time.After(flockPoll):
		}
	}
}

// Close releases the lock and closes the file.
func (l *flockFile) Close() error {
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	return l.f.Close()
}
