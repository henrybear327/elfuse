// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
)

// credResolveTimeout bounds how long credential resolution may run before the
// pull gives up. Resolution shells out to whatever helper the ambient Docker
// config names (credsStore / credHelpers), and go-containerregistry's default
// keychain discards the context around that exec, so a wedged helper (for
// example docker-credential-desktop with Docker Desktop not running) otherwise
// hangs the pull with no output and no way out but a signal.
const credResolveTimeout = 10 * time.Second

// timedKeychain runs an inner keychain's Resolve under a deadline. On
// timeout it returns an actionable error; the abandoned inner goroutine
// is reaped when the process exits.
type timedKeychain struct {
	inner   authn.Keychain
	timeout time.Duration
}

func (t timedKeychain) Resolve(r authn.Resource) (authn.Authenticator, error) {
	type resolved struct {
		auth authn.Authenticator
		err  error
	}
	// Buffered so the goroutine's send never blocks after a timeout, leaving
	// nothing to leak once the helper finally returns.
	ch := make(chan resolved, 1)
	go func() {
		auth, err := t.inner.Resolve(r)
		ch <- resolved{auth, err}
	}()

	select {
	case out := <-ch:
		return out.auth, out.err
	case <-time.After(t.timeout):
		return nil, fmt.Errorf(
			"resolving credentials for %s timed out after %s; a docker "+
				"credential helper (credsStore or credHelpers in "+
				"~/.docker/config.json) may be blocked. Retry with "+
				"DOCKER_CONFIG pointing at a directory whose config.json "+
				"omits it for an anonymous pull",
			r.String(), t.timeout)
	}
}
