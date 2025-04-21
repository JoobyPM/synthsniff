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

# Run critical benchmarks and fail on regressions
bench-ci:
	@set -e ;\
	go test ./internal/sniff -run='^$$' -bench='Analyse|RenderJSON|Scan' -benchmem > bench-ci-current.txt ;\
	echo ;\
	echo "Benchmark Budget Targets:" ;\
	echo "- analyse 1 KB / 1-rule      ≤ 13 000 ns/op    ≤ 10 allocs" ;\
	echo "- analyse 128 KB / 6-rules   ≤ 200 000 ns/op   ≤ 10 allocs" ;\
	echo "- RenderJSON 1 k results     ≤ 6 000 000 ns/op ≤ 13k allocs/op" ;\
	echo "- Scan 5 k files 8 CPU      ≥ 2x speed-up vs serial" ;\
	if [ -f bench-baseline.txt ]; then \
		if benchstat -h 2>&1 | grep -q -- '-delta-test'; then \
			benchstat -delta-test=U bench-baseline.txt bench-ci-current.txt ;\
		else \
			benchstat bench-baseline.txt bench-ci-current.txt ;\
		fi ;\
	fi

# Create benchmark baseline
bench-baseline:
	@echo "Creating benchmark baseline..."
	go test ./internal/sniff -run='^$$' -bench=. -benchmem > bench-baseline.txt
	@echo "Baseline created in bench-baseline.txt"

# Run benchmarks and compare with baseline (if exists)
bench-compare:
	@echo "Running current benchmarks..."
	@go test ./internal/sniff -run='^$$' -bench=. -benchmem > bench-current.txt
	@if [ -f bench-baseline.txt ]; then \
		echo "Comparing against baseline:"; \
		echo "--------------------------"; \
		echo "Baseline:"; \
		cat bench-baseline.txt; \
		echo "--------------------------"; \
		echo "Current:"; \
		cat bench-current.txt; \
		echo "--------------------------"; \
		echo "Note: For more detailed comparison, install benchstat:"; \
		echo "go install golang.org/x/perf/cmd/benchstat@latest"; \
	else \
		echo "No baseline found. Run 'make bench-baseline' first."; \
	fi

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

.PHONY: clean-bench
clean-bench:
	rm -rf internal/sniff/testdata/bench/gen
