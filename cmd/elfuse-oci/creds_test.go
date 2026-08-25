// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeDockerConfig points $DOCKER_CONFIG at a directory holding body as
// config.json for the rest of the test.
func writeDockerConfig(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dir)
}

// fakeHelper puts a docker-credential-<name> shell script on PATH.
func fakeHelper(t *testing.T, name, script string) {
	t.Helper()
	prependPath(t, filepath.Dir(writeShellStub(t, "docker-credential-"+name, script)))
}

func TestDockerCredentialsInlineAuth(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	writeDockerConfig(t, `{"auths": {"https://index.docker.io/v1/": {"auth": "`+auth+`"},
		"ghcr.io": {"username": "bob", "password": "pw"}}}`)
	for host, want := range map[string]string{
		"registry-1.docker.io": "alice s3cret",
		"ghcr.io":              "bob pw",
		"quay.io":              " ",
	} {
		user, pass, err := dockerCredentials(host)
		if err != nil || user+" "+pass != want {
			t.Errorf("%s: %q %q %v, want %q", host, user, pass, err, want)
		}
	}
}

func TestDockerCredentialsHelpers(t *testing.T) {
	fakeHelper(t, "found", `read url; echo "{\"ServerURL\":\"$url\",\"Username\":\"carol\",\"Secret\":\"tok\"}"`)
	fakeHelper(t, "missing", `echo "credentials not found in native keychain"; exit 1`)
	writeDockerConfig(t, `{"credsStore": "missing", "credHelpers": {"gcr.io": "found"}}`)
	user, pass, err := dockerCredentials("gcr.io")
	if err != nil || user != "carol" || pass != "tok" {
		t.Fatalf("credHelpers: %q %q %v", user, pass, err)
	}
	// The store-wide helper answers for every other registry; no entry
	// there is anonymous, not an error.
	user, pass, err = dockerCredentials("registry-1.docker.io")
	if err != nil || user != "" || pass != "" {
		t.Fatalf("credsStore miss: %q %q %v", user, pass, err)
	}
}

func TestDockerCredentialsHelperTimeout(t *testing.T) {
	fakeHelper(t, "stuck", `sleep 5`)
	cfg := dockerConfig{CredsStore: "stuck"}
	old := credResolveTimeout
	credResolveTimeout = 200 * time.Millisecond
	t.Cleanup(func() { credResolveTimeout = old })
	start := time.Now()
	_, _, err := cfg.lookup("example.com")
	if err == nil || !strings.Contains(err.Error(), "timed out after 200ms") {
		t.Fatalf("want a timeout error, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("the deadline did not stop the helper")
	}
}

func TestDockerCredentialsNoConfig(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	user, pass, err := dockerCredentials("registry-1.docker.io")
	if err != nil || user != "" || pass != "" {
		t.Fatalf("absent config must be anonymous: %q %q %v", user, pass, err)
	}
}
