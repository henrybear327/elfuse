# elfuse-oci: the Go OCI image CLI. Pure Go, so Linux CI builds and tests
# it too. A host without a Go toolchain still builds elfuse; the CLI is
# opted into all/lint/check only when a go new enough for go.mod is on
# PATH. The probe runs under GOTOOLCHAIN=local, so an older go fails go
# list instead of fetching the go.mod toolchain over the network; the
# explicit elfuse-oci target carries no such guard.

GO ?= go
HAVE_GO := $(shell GOTOOLCHAIN=local $(GO) list -m > /dev/null 2>&1 && echo yes)

OCI_BIN  := $(BUILD_DIR)/elfuse-oci
OCI_SRCS := $(shell find cmd/elfuse-oci -type f -name '*.go' ! -name '*_test.go' 2>/dev/null)

.PHONY: elfuse-oci oci-test oci-test-hdiutil oci-vet oci-fmt-check oci-lint

ifeq ($(HAVE_GO),yes)
all: elfuse-oci
check: oci-test
lint: oci-lint
endif

elfuse-oci: $(OCI_BIN)

# rm -f first: go build -o follows an existing symlink, so a stale
# build/elfuse-oci symlink would clobber its target.
$(OCI_BIN): go.mod go.sum $(OCI_SRCS) $(VERSION_DEPS) | $(BUILD_DIR)
	@echo "  GO      $@"
	$(Q)rm -f $@
	$(Q)$(GO) build -ldflags "-X main.version=$(VERSION)" -o $@ ./cmd/elfuse-oci

## Run the elfuse-oci Go tests (offline; ELFUSE_OCI_NETTEST=1 adds the
## registry round-trip)
oci-test:
	$(Q)$(GO) test -race ./cmd/elfuse-oci/

# Both GOOS values: the darwin pass compile-checks the sparsebundle files,
# the linux pass the stubs. GOARCH pinned so an amd64 host vets the same
# darwin/arm64 the runtime targets.
oci-vet:
	$(Q)GOOS=darwin GOARCH=arm64 $(GO) vet ./cmd/elfuse-oci/
	$(Q)GOOS=linux $(GO) vet ./cmd/elfuse-oci/

oci-fmt-check:
	$(Q)set -e; out=$$(gofmt -l cmd/elfuse-oci); if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; fi

## Check elfuse-oci formatting and vet both GOOS targets
oci-lint: oci-fmt-check oci-vet

## Run the real-hdiutil sparsebundle round-trip (macOS, a few seconds of
## disk arbitration)
oci-test-hdiutil:
	$(Q)ELFUSE_OCI_DARWIN_CS=1 $(GO) test -run TestDarwinCS -v ./cmd/elfuse-oci/
