package sniff

import (
	"os"
	"testing"
)

// Helper to capture stdout during benchmark tests
func captureStdoutBench(f func()) {
	old := os.Stdout
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return // Fall back to standard output if we can't open /dev/null
	}
	defer func() {
		_ = null.Close() // Ignore close error in benchmarks
	}()

	// Replace stdout with /dev/null
	os.Stdout = null

	f()

	// Restore stdout
	os.Stdout = old
}

// BenchmarkRenderJSON_1K_Results benchmarks JSON rendering with a large result set
func BenchmarkRenderJSON_1K_Results(b *testing.B) {
	// Create a large set of results (1000)
	results := makeResults(1000)

	// Configure for JSON output
	cfg := Config{
		JSON: true,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Capture stdout to avoid console output affecting benchmark
		captureStdoutBench(func() {
			Render(results, cfg)
		})
	}
}

// BenchmarkRenderText benchmarks various text rendering functions
func BenchmarkRenderText(b *testing.B) {
	// Test printUltra since it's called out specifically in requirements
	b.Run("printUltra", func(b *testing.B) {
		// Create a result with 10 detail entries
		r := makeResult(10, true)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Use benchPrintUltra from our helper file
			benchPrintUltra(r)
		}
	})

	// Test full rendering with ultra-verbose mode
	b.Run("RenderUltraVerbose", func(b *testing.B) {
		// Create 100 results for ultra-verbose output
		results := makeResults(100)

		cfg := Config{
			UltraVerbose: true,
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			captureStdoutBench(func() {
				Render(results, cfg)
			})
		}
	})

	// Test rendering with verbose mode
	b.Run("RenderVerbose", func(b *testing.B) {
		// Create 100 results with some smelly
		results := makeResults(100)

		cfg := Config{
			Verbose: true,
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			captureStdoutBench(func() {
				Render(results, cfg)
			})
		}
	})
}

// Benchmark various result processing functions
func BenchmarkResultFunctions(b *testing.B) {
	// Test hitCounts which is used for verbose output
	b.Run("hitCounts", func(b *testing.B) {
		r := makeResult(20, true) // Result with 20 details

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = hitCounts(r)
		}
	})

	// Test anySmelly which is called for every render operation
	b.Run("anySmelly", func(b *testing.B) {
		results := makeResults(1000) // 1000 results with ~1/3 smelly

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = anySmelly(results)
		}
	})
}
