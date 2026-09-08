VERSION ?= 0.3.0
GIT_COMMIT := $(shell git rev-parse --short HEAD)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT)
IMAGE ?= quay.io/shutthegoatup/gruff:$(VERSION)

# web/static/portal.css is generated but committed, so `go build` and the
# container build need no frontend toolchain. Run `make ui` after editing
# templates or web/src; CI fails if the committed file is stale.
TAILWIND_VERSION := v4.3.3
TAILWIND := .cache/tailwindcss-$(TAILWIND_VERSION)
TAILWIND_URL := https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-linux-x64

.PHONY: all build test lint vulncheck check ui ui-check container container-check clean

all: check build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o gruff ./cmd/gruff

test:
	go test -race ./...

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

check: lint ui-check test

$(TAILWIND):
	@mkdir -p .cache
	curl -sSfL -o $@ $(TAILWIND_URL)
	chmod +x $@

ui: $(TAILWIND)
	$(TAILWIND) -i web/src/input.css -o web/static/portal.css --minify

# Regenerate into a temporary file and fail if it differs from what is committed.
ui-check: $(TAILWIND)
	@$(TAILWIND) -i web/src/input.css -o .cache/portal.css --minify >/dev/null 2>&1
	@cmp -s .cache/portal.css web/static/portal.css \
		|| { echo "web/static/portal.css is stale; run 'make ui' and commit the result"; exit 1; }

container:
	docker build -f build/package/Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(IMAGE) .

# scratch has no shell, so the image is inspected from outside it. Both checks
# exist because both have been broken before: the image once could not start at
# all, and it once shipped without the roots OIDC sign-in needs.
container-check: container
	docker run --rm $(IMAGE) --version
	@id=$$(docker create $(IMAGE)); \
		docker cp $$id:/etc/ssl/certs/ca-certificates.crt - >/dev/null 2>&1; \
		rc=$$?; docker rm -f $$id >/dev/null; \
		test $$rc -eq 0 \
			|| { echo "image has no trust store; OIDC sign-in cannot verify the provider"; exit 1; }

clean:
	rm -f gruff
	rm -rf .cache
