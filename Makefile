GO ?= go
BIN := playground policycheck

.PHONY: all build test run sync-assets clean

all: sync-assets build test

build: sync-assets
	$(GO) build ./...
	$(GO) build -o bin/playground ./cmd/playground
	$(GO) build -o bin/policycheck ./cmd/policycheck

test: sync-assets
	$(GO) vet ./...
	$(GO) test ./...

run: build
	./bin/playground

# Keep the embedded copies in internal/server/assets identical to the
# canonical files a reader sees in policies/ and examples/evidence/.
sync-assets:
	mkdir -p internal/server/assets/policies internal/server/assets/evidence
	cp policies/*.rego internal/server/assets/policies/
	cp examples/evidence/*.json internal/server/assets/evidence/

clean:
	rm -rf bin
