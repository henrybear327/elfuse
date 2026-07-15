// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// TestInspectHuman asserts the human-readable summary surfaces the ref,
// platform, and command. Substring checks (not column spacing) keep it robust
// to formatting tweaks.
func TestInspectHuman(t *testing.T) {
	s := openTestStore(t)
	ref := "local:tiny"
	if _, err := s.addImage(ref, tinyImage(t)); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := inspect(&buf, s, ref, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"local:tiny", "Platform:", "linux/arm64", "Cmd:", "/hello"} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect output missing %q:\n%s", want, out)
		}
	}
}

// TestInspectJSON asserts --json emits a valid v1.ConfigFile with the tiny
// image's architecture/os/cmd.
func TestInspectJSON(t *testing.T) {
	s := openTestStore(t)
	ref := "local:tiny"
	if _, err := s.addImage(ref, tinyImage(t)); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := inspect(&buf, s, ref, true); err != nil {
		t.Fatal(err)
	}
	var cf v1.ConfigFile
	if err := json.Unmarshal(buf.Bytes(), &cf); err != nil {
		t.Fatalf("json unmarshal: %v (raw %q)", err, buf.String())
	}
	if cf.Architecture != "arm64" {
		t.Errorf("Architecture: got %q, want arm64", cf.Architecture)
	}
	if cf.OS != "linux" {
		t.Errorf("OS: got %q, want linux", cf.OS)
	}
	if len(cf.Config.Cmd) != 1 || cf.Config.Cmd[0] != "/hello" {
		t.Errorf("Cmd: got %v, want [/hello]", cf.Config.Cmd)
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

func TestInspectHumanIncludesCreatedEnvAndLayers(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:rich", imageWithRichConfig(t)); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := inspect(&buf, s, "local:rich", false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Ref:         local:rich",
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

// TestInspectHoldsStoreLock pins #2: inspect resolves and reads image metadata
// under the store lock, so a concurrent rmi cannot delete blobs mid-inspect.
// The proof is that inspect blocks while another holder keeps the lock and
// completes once it is released.
func TestInspectHoldsStoreLock(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:tiny", tinyImage(t)); err != nil {
		t.Fatal(err)
	}
	unlock, err := s.lock()
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		var buf bytes.Buffer
		done <- inspect(&buf, s, "local:tiny", false)
	}()

	select {
	case <-done:
		unlock()
		t.Fatal("inspect completed while the store lock was held; it does not take the lock")
	case <-time.After(150 * time.Millisecond):
	}

	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("inspect after unlock: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inspect did not complete after the store lock was released")
	}
}

// TestInspectAndListAgreeOnVariant pins #13: an image with a platform variant
// (linux/arm/v7) must show the full os/arch/variant in inspect, matching list,
// not the truncated os/arch.
func TestInspectAndListAgreeOnVariant(t *testing.T) {
	s := openTestStore(t)
	img := tinyImage(t)
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Architecture = "arm"
	cfg.Variant = "v7"
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:v7", img); err != nil {
		t.Fatal(err)
	}

	var ins bytes.Buffer
	if err := inspect(&ins, s, "local:v7", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ins.String(), "linux/arm/v7") {
		t.Fatalf("inspect platform missing variant:\n%s", ins.String())
	}
	var lst bytes.Buffer
	if err := list(&lst, s, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lst.String(), "linux/arm/v7") {
		t.Fatalf("list platform missing variant:\n%s", lst.String())
	}
}

func TestInspectMissingRefAndConfigErrors(t *testing.T) {
	s := openTestStore(t)
	if err := inspect(&bytes.Buffer{}, s, "local:missing", false); err == nil || !strings.Contains(err.Error(), "not pulled") {
		t.Fatalf("inspect missing ref err = %v, want not pulled", err)
	}

	img := tinyImage(t)
	config, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.addImage("local:tiny", img); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(blobPath(s.root, config.String())); err != nil {
		t.Fatal(err)
	}
	if err := inspect(&bytes.Buffer{}, s, "local:tiny", false); err == nil {
		t.Fatal("inspect with missing config succeeded, want error")
	}
}

// failingWriter fails every write, standing in for a closed pipe or a full
// filesystem behind a redirect.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("sink failed") }

func TestInspectPropagatesWriteErrors(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.addImage("local:tiny", tinyImage(t)); err != nil {
		t.Fatal(err)
	}
	if err := inspect(failingWriter{}, s, "local:tiny", true); err == nil {
		t.Fatal("inspect --json exited clean on a failed write, want error")
	}
	if err := inspect(failingWriter{}, s, "local:tiny", false); err == nil {
		t.Fatal("inspect summary exited clean on a failed write, want error")
	}
}
