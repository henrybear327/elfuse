// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// TestCheckImagePlatform pins the post-pull config check: a single-manifest
// ref bypasses crane.WithPlatform, so a config disagreeing with the request
// must be rejected here, and the variant only counts when the request
// named one.
func TestCheckImagePlatform(t *testing.T) {
	withConfig := func(os, arch, variant string) v1.Image {
		img, err := mutate.ConfigFile(tinyImage(t), &v1.ConfigFile{
			OS:           os,
			Architecture: arch,
			Variant:      variant,
		})
		if err != nil {
			t.Fatal(err)
		}
		return img
	}
	cases := []struct {
		name    string
		want    Platform
		img     v1.Image
		wantErr string
	}{
		{"match", Platform{OS: "linux", Arch: "arm64"}, withConfig("linux", "arm64", ""), ""},
		{"config variant tolerated", Platform{OS: "linux", Arch: "arm64"}, withConfig("linux", "arm64", "v8"), ""},
		{"requested variant matches", Platform{OS: "linux", Arch: "arm64", Variant: "v8"}, withConfig("linux", "arm64", "v8"), ""},
		{"os mismatch", Platform{OS: "linux", Arch: "arm64"}, withConfig("darwin", "arm64", ""), "image is darwin/arm64"},
		{"arch mismatch", Platform{OS: "linux", Arch: "arm64"}, withConfig("linux", "amd64", ""), "image is linux/amd64"},
		{"requested variant mismatch", Platform{OS: "linux", Arch: "arm64", Variant: "v8"}, withConfig("linux", "arm64", "v9"), "want linux/arm64/v8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkImagePlatform(tc.want, tc.img)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkImagePlatform = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkImagePlatform = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
