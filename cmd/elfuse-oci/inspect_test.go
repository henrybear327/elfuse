// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// TestInspectJSON pins that --json emits the raw config document itself,
// not a re-marshal: a key ggcr's ConfigFile does not model, planted into
// the stored blob, must survive to the output byte for byte.
func TestInspectJSON(t *testing.T) {
	s := openTestStore(t)
	ref := "local:tiny"
	img := tinyImage(t)
	seedImage(t, s, ref, img)

	ch, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	p := blobPath(s.root, ch.String())
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	planted := append([]byte(`{"x-elfuse-test":1,`), raw[1:]...)
	if err := os.WriteFile(p, planted, 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := inspect(&buf, s, ref, defaultPlatform, true); err != nil {
		t.Fatal(err)
	}
	want := append(planted, '\n')
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("inspect --json = %q, want the stored blob verbatim %q", buf.Bytes(), want)
	}
}

func imageWithRichConfig(t *testing.T) v1.Image {
	t.Helper()
	img := tinyImage(t)
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Created = v1.Time{Time: time.Date(2026, 7, 9, 12, 34, 56, 0, time.FixedZone("test", 2*60*60))}
	cfg.Config.Entrypoint = []string{"/entry"}
	cfg.Config.Cmd = []string{"arg"}
	cfg.Config.Env = []string{"A=1", "B=2"}
	cfg.Config.WorkingDir = "/work"
	cfg.Config.User = "1000:1000"
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// TestInspectHumanIncludesCreatedEnvAndLayers is the sole human-summary
// shape test; it matches by substring, so column spacing may change.
func TestInspectHumanIncludesCreatedEnvAndLayers(t *testing.T) {
	s := openTestStore(t)
	seedImage(t, s, "local:rich", imageWithRichConfig(t))
	var buf bytes.Buffer
	if err := inspect(&buf, s, "local:rich", defaultPlatform, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Ref:         local:rich",
		"Platform:    linux/arm64",
		"Created:     2026-07-09T10:34:56Z",
		"Entrypoint:  [/entry]",
		"Cmd:         [arg]",
		"WorkingDir:  /work",
		"User:        1000:1000",
		"Env (2):",
		"A=1",
		"Layers (1):",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("inspect output missing %q:\n%s", want, out)
		}
	}
}

// TestInspectMissingRefAndConfigErrors pins that a never-pulled ref and a
// missing config blob both fail loudly; empty output with exit 0 would
// hide store corruption.
func TestInspectMissingRefAndConfigErrors(t *testing.T) {
	s := openTestStore(t)
	if err := inspect(&bytes.Buffer{}, s, "local:missing", defaultPlatform, false); err == nil || !strings.Contains(err.Error(), "not pulled") {
		t.Fatalf("inspect missing ref err = %v, want not pulled", err)
	}

	img := tinyImage(t)
	config, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	seedImage(t, s, "local:tiny", img)
	if err := os.Remove(blobPath(s.root, config.String())); err != nil {
		t.Fatal(err)
	}
	if err := inspect(&bytes.Buffer{}, s, "local:tiny", defaultPlatform, false); err == nil {
		t.Fatal("inspect with missing config succeeded, want error")
	}
}

// failingWriter fails every write, standing in for a closed pipe or a full
// filesystem behind a redirect.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("sink failed") }

// TestInspectPropagatesWriteErrors pins that a failed output write
// surfaces as an error in both output modes.
func TestInspectPropagatesWriteErrors(t *testing.T) {
	s := openTestStore(t)
	seedImage(t, s, "local:tiny", tinyImage(t))
	if err := inspect(failingWriter{}, s, "local:tiny", defaultPlatform, true); err == nil {
		t.Fatal("inspect --json exited clean on a failed write, want error")
	}
	if err := inspect(failingWriter{}, s, "local:tiny", defaultPlatform, false); err == nil {
		t.Fatal("inspect summary exited clean on a failed write, want error")
	}
}
