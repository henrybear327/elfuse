// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker-credential-helpers/client"
	"github.com/docker/docker-credential-helpers/credentials"
)

// credResolveTimeout bounds one credential-helper run even on an unbounded
// pull: a wedged helper (docker-credential-desktop with Docker Desktop
// not running) would otherwise hang the pull with no output.
var credResolveTimeout = 10 * time.Second

// hubIndex is the key docker login stores Docker Hub credentials under;
// the registry itself answers as registry-1.docker.io.
const hubIndex = "https://index.docker.io/v1/"

// dockerCredentials is the authorizer's credential callback: the ambient
// docker config's entry for host, through its credential helper when one
// is configured, anonymous (empty) when the config or the entry is absent.
func dockerCredentials(host string) (string, string, error) {
	cfg, err := loadDockerConfig()
	if err != nil {
		return "", "", err
	}
	return cfg.lookup(host)
}

// dockerConfig is the subset of config.json that names credentials:
// inline auths, one helper for every registry, or a helper per registry.
type dockerConfig struct {
	Auths       map[string]dockerAuth `json:"auths"`
	CredsStore  string                `json:"credsStore"`
	CredHelpers map[string]string     `json:"credHelpers"`
}

type dockerAuth struct {
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// loadDockerConfig reads $DOCKER_CONFIG/config.json, defaulting to
// ~/.docker, the same resolution docker login writes through. A missing
// file is an empty config.
func loadDockerConfig() (dockerConfig, error) {
	var cfg dockerConfig
	dir := os.Getenv("DOCKER_CONFIG")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return cfg, nil
		}
		dir = filepath.Join(home, ".docker")
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if os.IsNotExist(err) {
		return cfg, nil
	} else if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("docker config: %w", err)
	}
	return cfg, nil
}

// registryKey maps the host the registry answered as to the key docker
// stores its credentials under.
func registryKey(host string) string {
	switch host {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return hubIndex
	}
	return host
}

// hostname strips a config key to its host: docker accepts keys with or
// without a scheme and a trailing path ("https://gcr.io/" and "gcr.io"
// name the same registry).
func hostname(key string) string {
	if _, rest, ok := strings.Cut(key, "://"); ok {
		key = rest
	}
	host, _, _ := strings.Cut(key, "/")
	return host
}

// lookup resolves host through the config: the helper named for the
// registry, else the store-wide helper, else the inline auths entry.
func (c dockerConfig) lookup(host string) (string, string, error) {
	key := registryKey(host)
	helper := c.CredsStore
	for k, h := range c.CredHelpers {
		if hostname(k) == hostname(key) {
			helper = h
			break
		}
	}
	if helper != "" {
		return runHelper(helper, key)
	}
	for k, a := range c.Auths {
		if hostname(k) != hostname(key) {
			continue
		}
		if a.Auth == "" {
			return a.Username, a.Password, nil
		}
		raw, err := base64.StdEncoding.DecodeString(a.Auth)
		if err != nil {
			return "", "", fmt.Errorf("docker config: auth for %s: %w", k, err)
		}
		user, pass, ok := strings.Cut(string(raw), ":")
		if !ok {
			return "", "", fmt.Errorf("docker config: auth for %s is not user:password", k)
		}
		return user, pass, nil
	}
	return "", "", nil
}

// runHelper asks docker-credential-<name> for serverURL over the helper
// protocol; a helper with no entry means anonymous, any other failure
// is the pull's.
func runHelper(name, serverURL string) (string, string, error) {
	creds, err := client.Get(helperProgram(name), serverURL)
	if credentials.IsErrCredentialsNotFound(err) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("docker-credential-%s: %w", name, err)
	}
	return creds.Username, creds.Secret, nil
}

// helperProgram runs the helper under a deadline, which client's own
// shell program lacks. WaitDelay closes the pipes once the deadline kills
// the helper, or a child left holding stdout would keep Output waiting.
func helperProgram(name string) client.ProgramFunc {
	return func(args ...string) client.Program {
		ctx, cancel := context.WithTimeout(context.Background(), credResolveTimeout)
		cmd := exec.CommandContext(ctx, "docker-credential-"+name, args...)
		cmd.WaitDelay = time.Second
		cmd.Stderr = os.Stderr
		return &boundedProgram{cmd: cmd, ctx: ctx, cancel: cancel}
	}
}

type boundedProgram struct {
	cmd    *exec.Cmd
	ctx    context.Context
	cancel context.CancelFunc
}

func (p *boundedProgram) Input(in io.Reader) { p.cmd.Stdin = in }

func (p *boundedProgram) Output() ([]byte, error) {
	defer p.cancel()
	out, err := p.cmd.Output()
	if errors.Is(p.ctx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("timed out after %s", credResolveTimeout)
	}
	return out, err
}
