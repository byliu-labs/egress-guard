.PHONY: build bar app test test-integration clean install-dev embed catalog-build embed-exempt

GOFLAGS := -trimpath
LDFLAGS := -s -w
BIN := bin/egress-guard
DESTDIR ?= /usr/local/bin

embed:
	cp configs/defaults.toml internal/config/defaults_embedded.toml

build: embed
	@mkdir -p bin
	go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $(BIN) ./cmd/egress-guard

bar: embed
	@mkdir -p bin
	go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o bin/egress-guard-bar ./cmd/egress-guard-bar

app: build bar
	bash packaging/mac/build-app.sh

catalog-build:
	@mkdir -p bin
	go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o bin/catalog-build ./cmd/catalog-build

embed-exempt: catalog-build
	bin/catalog-build embed-exempt --exempt catalog/exempt --out internal/exempt/defaults_embedded.toml

test: embed
	go test -race -count=1 ./...

test-integration: embed
	go test -race -count=1 -tags=integration ./tests/integration/...

clean:
	rm -rf bin
	rm -f internal/config/defaults_embedded.toml

# Only the install step escalates. `build` is a prerequisite, so the compile
# always runs as the invoking user — `sudo make install-dev` would compile as
# root, leaving a root-owned internal/config/defaults_embedded.toml in the
# worktree and populating root's build cache. `install` unlinks and recreates
# rather than writing in place, so it replaces a root-owned binary from an
# earlier privileged install (which a bare `cp` cannot) and survives the
# destination being busy.
install-dev: build
	@if [ -w $(DESTDIR) ] && { [ ! -e $(DESTDIR)/egress-guard ] || [ -w $(DESTDIR)/egress-guard ]; }; then \
		install -m 0755 $(BIN) $(DESTDIR)/egress-guard; \
	else \
		echo "==> $(DESTDIR)/egress-guard is not writable by $$(id -un); escalating with sudo"; \
		sudo install -m 0755 $(BIN) $(DESTDIR)/egress-guard; \
	fi
	@echo "Installed $(DESTDIR)/egress-guard"
