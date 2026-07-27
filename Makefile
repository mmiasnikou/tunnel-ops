# Every subdirectory of cmd/ is a separate binary. Adding a new tool means
# creating cmd/<name>/ — nothing in this file has to change.
CMDS := $(notdir $(wildcard cmd/*))

# git describe yields v1.2.3 on a tag, v1.2.3-4-gabc1234-dirty in between.
# Falls back to "dev" when git is absent or the repo has no tags yet.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64

# .PHONY marks targets that do not produce a file of that name. Without it
# make would see no file called "test" and try to build one.
.PHONY: help all fmt vet lint test race cover build dist install clean

help: ## list available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  binaries: $(CMDS)"
	@echo "  version:  $(VERSION)"

all: fmt vet test build ## format, vet, test and build

fmt: ## format the code in place
	gofmt -w .

lint: ## fail if the code is not formatted (for CI)
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "not formatted:"; echo "$$out"; exit 1; fi

vet: ## static analysis
	go vet ./...

test: ## unit tests
	go test ./...

race: ## unit tests with the race detector
	go test -race ./...

cover: ## test coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

build: ## build every binary for the host platform into bin/
	@mkdir -p bin
	@for c in $(CMDS); do \
	  echo "  -> bin/$$c"; \
	  CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath \
	    -o bin/$$c ./cmd/$$c || exit 1; \
	done

install: build ## copy every binary into /usr/local/bin
	@for c in $(CMDS); do \
	  install -m 0755 bin/$$c /usr/local/bin/$$c; \
	  echo "  installed /usr/local/bin/$$c"; \
	done

dist: clean ## cross-compile every binary for every platform + SHA256SUMS
	@mkdir -p dist
	@for c in $(CMDS); do \
	  for p in $(PLATFORMS); do \
	    os=$${p%/*}; arch=$${p#*/}; ext=""; \
	    if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
	    echo "  -> $$c $$os/$$arch"; \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	      go build -ldflags="$(LDFLAGS)" -trimpath \
	      -o dist/$${c}_$${os}_$${arch}$$ext ./cmd/$$c || exit 1; \
	  done; \
	done
	@cd dist && sha256sum * > SHA256SUMS
	@echo ""
	@ls -lh dist/

clean: ## remove build artifacts
	rm -rf bin dist coverage.out
