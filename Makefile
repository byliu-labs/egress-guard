.PHONY: build bar app test test-integration clean install-dev embed catalog-build embed-exempt

GOFLAGS := -trimpath
LDFLAGS := -s -w
BIN := bin/egress-guard

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

install-dev: build
	cp $(BIN) /usr/local/bin/egress-guard
	@echo "Installed /usr/local/bin/egress-guard"
