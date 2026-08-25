// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestInspectSummary(t *testing.T) {
	created := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	s, d := storeWithImage(t, "demo:1", testImage{
		created: &created,
		config: ocispec.ImageConfig{
			Entrypoint: []string{"/bin/app"},
			Cmd:        []string{"--serve"},
			WorkingDir: "/srv",
			User:       "app",
			Env:        []string{"A=1", "B=2"},
		},
	})
	var out bytes.Buffer
	if err := inspect(context.Background(), &out, s, "demo:1", defaultPlatform, false); err != nil {
		t.Fatal(err)
	}
	mustContain(t, out.String(),
		"Ref:", "demo:1",
		"Digest:", d,
		"Platform:", "linux/arm64",
		"Created:", "2026-01-02T15:04:05Z",
		"[/bin/app]", "[--serve]", "/srv", "app",
		"Env (2):", "A=1", "B=2",
		"Layers (1):")
}

// TestInspectSummaryQuotesControlBytes pins that a config string carrying
// a newline or an escape sequence is quoted onto its own line rather than
// forging a record or reaching the terminal raw.
func TestInspectSummaryQuotesControlBytes(t *testing.T) {
	s, _ := storeWithImage(t, "demo:1", testImage{
		config: ocispec.ImageConfig{
			Cmd:  []string{"\x1b[2Jclear"},
			User: "app\nRef:        forged",
			Env:  []string{"PLAIN=1", "A=b\nUser:       root"},
		},
	})
	var out bytes.Buffer
	if err := inspect(context.Background(), &out, s, "demo:1", defaultPlatform, false); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	mustContain(t, got, `["\x1b[2Jclear"]`, `"app\nRef:        forged"`, "  PLAIN=1\n", `  "A=b\nUser:       root"`)
	for _, raw := range []string{"\x1b", "\nRef:        forged", "\nUser:       root", "\nDigest:     forged"} {
		if strings.Contains(got, raw) {
			t.Errorf("summary carries %q raw:\n%s", raw, got)
		}
	}
}

// TestInspectJSONRawBytes pins that --json emits the stored config blob
// verbatim: a key the parsed struct does not model must survive.
func TestInspectJSONRawBytes(t *testing.T) {
	raw := []byte(`{"os":"linux","architecture":"arm64","config":{},"vendorExtension":{"x":1}}`)
	s, _ := storeWithImage(t, "demo:1", testImage{rawConfig: raw})
	var out bytes.Buffer
	if err := inspect(context.Background(), &out, s, "demo:1", defaultPlatform, true); err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, raw...), '\n')
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("json output not verbatim:\n%s", out.Bytes())
	}
}

func TestInspectMissingRefErrors(t *testing.T) {
	s := tempStore(t)
	var out bytes.Buffer
	if err := inspect(context.Background(), &out, s, "absent:1", defaultPlatform, false); err == nil {
		t.Fatal("missing ref must error")
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must stay empty on error, got %q", out.String())
	}
}

// failWriter fails after n bytes, modeling a closed pipe mid-summary.
type failWriter struct{ n int }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, errClosedPipe
	}
	if len(p) > w.n {
		n := w.n
		w.n = 0
		return n, errClosedPipe
	}
	w.n -= len(p)
	return len(p), nil
}

var errClosedPipe = errors.New("closed pipe")

func TestInspectWriteErrorPropagates(t *testing.T) {
	s, _ := storeWithImage(t, "demo:1", testImage{})
	for _, asJSON := range []bool{false, true} {
		if err := inspect(context.Background(), &failWriter{n: 3}, s, "demo:1", defaultPlatform, asJSON); err == nil {
			t.Fatalf("asJSON=%v: failed write must not exit 0", asJSON)
		}
	}
}
