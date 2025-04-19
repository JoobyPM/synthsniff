# Declare phony targets so they're not confused with real files/folders
.PHONY: all generate build run run-debug clean test test-coverage bench bench-mem lint check

# Default target when type "make"
all: build

generate:
	go generate ./... && go fmt ./... && go vet ./...

# Format
format:
	go fmt ./...

# Static analysis (`staticcheck`)
static:
	staticcheck ./...

# Lint
lint:
	golangci-lint run ./... && go vet ./... && golint ./...

# Full check
check: format static lint test

# Run tests
test:
	go test ./...

# Run the simple e2e test
test-simple-e2e:
	./scripts/simple.e2e.sh

# Run tests with coverage
test-coverage:
	go test ./... -coverprofile=coverage.out && go tool cover -func=coverage.out

# Interactive coverage
test-coverage-interactive:
	go tool cover -html=coverage.out

# Run benchmarks
bench:
	go test ./... -bench=.

# Run benchmarks with memory allocation statistics for benchmarks.
bench-mem:
	go test ./... -bench=. -benchmem

# Build a binary called "sniff4ai" in `cmd/sniff4ai` directory
build: generate
	go build -o cmd/sniff4ai/sniff4ai cmd/sniff4ai/main.go

# Build binary for production with basic obfuscation
build-prod: generate
	go build -o cmd/sniff4ai/sniff4ai -ldflags="-s -w" cmd/sniff4ai/main.go

# Run the compiled binary
run: build
	./cmd/sniff4ai/sniff4ai

# Cleanup for good measure
clean:
	rm -f cmd/sniff4ai/sniff4ai && rm -f coverage.out
