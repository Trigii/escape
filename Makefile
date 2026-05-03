# Makefile — escape
#
# Common targets:
#   make build     # local binary
#   make test      # run unit tests
#   make vet       # go vet
#   make all       # vet + test + build
#   make release   # cross-compile for linux/amd64, linux/arm64, darwin/arm64

BINARY    := escape
PKG       := github.com/tristanvaquero/escape
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.0-dev)
LDFLAGS   := -s -w -X $(PKG)/internal/cli.Version=$(VERSION)
BUILDDIR  := dist

.PHONY: all build test vet clean release fmt lab lab-down

all: vet test build

build:
	@mkdir -p $(BUILDDIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/$(BINARY) ./cmd/escape

test:
	go test -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf $(BUILDDIR)

release: clean
	@mkdir -p $(BUILDDIR)
	GOOS=linux  GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/$(BINARY)-linux-amd64  ./cmd/escape
	GOOS=linux  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/$(BINARY)-linux-arm64  ./cmd/escape
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/$(BINARY)-darwin-arm64 ./cmd/escape
	@ls -lh $(BUILDDIR)

# Run the lab — assumes you've already done `make release`.
lab:
	@test -x $(BUILDDIR)/$(BINARY)-linux-amd64 || $(MAKE) release
	cd lab && ./run.sh

lab-down:
	cd lab && ./teardown.sh
