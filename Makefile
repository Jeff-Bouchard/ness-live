# ness-live — zero-dependency Go userland + one-screen web observatory
BIN     := bin
PKGS    := ./cmd/...
GOFLAGS := -trimpath

.PHONY: all build install test race vet cross clean run-collector run-bridge serve

all: vet test build

build:
	@mkdir -p $(BIN)
	go build $(GOFLAGS) -o $(BIN)/nesscollector ./cmd/nesscollector
	go build $(GOFLAGS) -o $(BIN)/nessbridge    ./cmd/nessbridge
	@echo "built -> $(BIN)/"

install:
	go install $(GOFLAGS) $(PKGS)

test:
	go test $(PKGS)

race:
	go test -race $(PKGS)

vet:
	go vet $(PKGS)

# linux/arm64 for the Tanix boxes, windows/amd64 for Git Bash
cross:
	@mkdir -p $(BIN)
	GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -o $(BIN)/nesscollector-linux-arm64        ./cmd/nesscollector
	GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -o $(BIN)/nesscollector-linux-amd64        ./cmd/nesscollector
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o $(BIN)/nesscollector-windows-amd64.exe  ./cmd/nesscollector
	GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -o $(BIN)/nessbridge-linux-arm64           ./cmd/nessbridge
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o $(BIN)/nessbridge-windows-amd64.exe     ./cmd/nessbridge

run-collector: build
	./$(BIN)/nesscollector

run-bridge: build
	./$(BIN)/nessbridge -ws :7666 -listen :6666

# the web observatory is a single static file; serve it however you like
serve:
	cd web && python3 -m http.server 8080

clean:
	rm -rf $(BIN) dist
