# Benchmark Suite for SynthSniff

This document describes the performance benchmark suite for the SynthSniff tool and outlines the performance budgets we aim to maintain.

## Performance Budgets

The following performance budgets are established to ensure the scanner maintains good performance characteristics:

| Benchmark | Target | Description |
|-----------|--------|-------------|
| `analyse` 1 KB / 1-rule | ≤ 13 000 ns/op, ≤ 10 allocs | Hot loop performance for small files |
| `analyse` 128 KB / 6-rules | ≤ 200 000 ns/op, ≤ 10 allocs | Hot loop performance for medium-sized files |
| `RenderJSON` 1K results | ≤ 6 000 000 ns/op, ≤ 13k allocs/op | Efficient CI reporting |
| `Scan` 5K files, 8 CPUs | ≥ 2× speed-up vs serial | Parallel throughput |

## Benchmark Suite Components

The benchmark suite tests several key components:

1. **Hot Loop Performance** - The `analyse` function which processes individual files
   ```
   BenchmarkAnalyse_1KB_1Rule
   BenchmarkAnalyse_128KB_6Rules
   ```

2. **Rule Checks** - The rule applicability and threshold functions
   ```
   BenchmarkRuleChecks/appliesToExt
   BenchmarkRuleChecks/passesThresholds
   ```

3. **JSON Rendering** - CI-friendly JSON output for automation
   ```
   BenchmarkRenderJSON_1K_Results
   ```

4. **Text Rendering** - User-friendly output formats
   ```
   BenchmarkRenderText/printUltra
   BenchmarkRenderText/RenderUltraVerbose
   BenchmarkRenderText/RenderVerbose
   ```

5. **Directory Walk & Parallelism** - Multi-CPU scaling
   ```
   BenchmarkScan/CPUs/c1
   BenchmarkScan/CPUs/c2
   BenchmarkScan/CPUs/c4
   BenchmarkScan/CPUs/c8
   ```

## Running Benchmarks

Several Makefile targets are available for benchmarking:

- `make bench` - Run all benchmarks
- `make bench-mem` - Run benchmarks with memory allocation statistics
- `make bench-ci` - Run critical benchmarks and fail if they don't meet targets
- `make bench-compare` - Compare current benchmark results against saved baseline

## Benchmark Data Generation

The benchmark suite uses a synthetic corpus to ensure consistent and reproducible results:

- An auto-generated corpus of 5,000 files:
  - Files between 128-512 bytes in size
  - Nested in directories with varying depth
  - Various file extensions (.txt, .md, .go, .py, .js, etc.)
  - Approximately 20% of files containing AI detector patterns
  - Corpus is automatically created in `testdata/bench/gen/` on first benchmark run (relative to package directory)
  - Corpus is excluded from Git via `.gitignore`
  - Can be cleaned up with `make clean-bench` when needed

- In-memory test data:
  - Generated rule sets with controllable complexity
  - Synthetic results for rendering benchmarks
  - Readable content with proper sentences

No disk I/O is performed within the benchmark measurement loops to ensure consistent results. The benchmark files are created only once at initialization time and reused across benchmark runs.

## Maintaining Baselines

To update the baseline benchmarks after making improvements:

1. Run the benchmarks to verify performance meets targets:
   ```
   make bench-ci
   ```

2. If all tests pass, create a new baseline:
   ```
   make bench-compare
   ```
   (This will create a new baseline if none exists)

3. To explicitly update an existing baseline:
   ```
   rm bench-baseline.txt
   make bench-compare
   ```

## Interpreting Results

When viewing benchmark results:

- **Ops/sec**: Higher is better
- **ns/op**: Lower is better
- **B/op**: Lower is better
- **allocs/op**: Lower is better

The `bench-ci` target will automatically check if benchmarks meet their targets and fail the build if they don't.
