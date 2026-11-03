# cve2026-98432-exp — build & test

BIN      := cve2026-98432-exp
VERSION  := 0.3.0
LDFLAGS  := -s -w -X main.version=$(VERSION)
GO       ?= go

.PHONY: all build static test vet dry dist clean

all: build

# Host build (static, CGO off).
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) .

# Portable artifact: linux/amd64 static.
static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) .

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

# Print the exact packets; sends nothing, no sockets opened.
dry: build
	./$(BIN) --dry-run

dist: static
	mkdir -p dist
	cp $(BIN) dist/$(BIN)
	cp README.md LICENSE DISCLAIMER.md dist/
	cp lab/attack-lab.toml dist/attack.example.toml
	cd dist && tar czf cve2026-98432-exp-linux-amd64.tar.gz \
		$(BIN) README.md LICENSE DISCLAIMER.md attack.example.toml
	@ls -la dist/

clean:
	rm -f $(BIN)
	rm -rf dist
