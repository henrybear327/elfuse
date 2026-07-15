// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
)

// fakeResource is a minimal authn.Resource for driving timedKeychain.Resolve.
type fakeResource struct{ s string }

func (f fakeResource) String() string      { return f.s }
func (f fakeResource) RegistryStr() string { return f.s }

// blockingKeychain models a wedged credential helper: Resolve never returns
// until the test releases it.
type blockingKeychain struct{ release chan struct{} }

func (b blockingKeychain) Resolve(authn.Resource) (authn.Authenticator, error) {
	<-b.release
	return authn.Anonymous, nil
}

// A wedged helper must surface a bounded, actionable error rather than hang.
// The old failure was an indefinite block with no output; a regression here
// reads as Resolve never returning within the timeout.
func TestTimedKeychainReportsTimeout(t *testing.T) {
	inner := blockingKeychain{release: make(chan struct{})}
	defer close(inner.release) // let the parked goroutine exit after the test

	tk := timedKeychain{inner: inner, timeout: 50 * time.Millisecond}

	done := make(chan error, 1)
	go func() {
		_, err := tk.Resolve(fakeResource{s: "registry.example/img"})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a timeout error, got nil")
		}
		if !strings.Contains(err.Error(), "DOCKER_CONFIG") {
			t.Fatalf("error does not name the workaround: %v", err)
		}
		if !strings.Contains(err.Error(), "registry.example/img") {
			t.Fatalf("error does not name the resource: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Resolve did not return within the timeout; it hung")
	}
}

// A helper that answers promptly must pass its result through untouched, so
// registry auth is unchanged when nothing is wedged.
func TestTimedKeychainPassesThroughFastResult(t *testing.T) {
	ready := blockingKeychain{release: make(chan struct{})}
	close(ready.release) // already released: Resolve returns immediately

	tk := timedKeychain{inner: ready, timeout: 2 * time.Second}
	auth, err := tk.Resolve(fakeResource{s: "registry.example/img"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth != authn.Anonymous {
		t.Fatalf("authenticator = %v, want the inner keychain's result", auth)
	}
}
