package sniff

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Ensures testdata/bench directory is created only once
var benchDataInitOnce sync.Once

// Collection of Lorem Ipsum paragraphs to ensure readable content
var paragraphs = []string{
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.",
	"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
	"Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo.",
	"Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet.",
	"At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident.",
	"The quick brown fox jumps over the lazy dog. This pangram contains all the letters of the English alphabet. It's often used for testing fonts, keyboards, and OCR applications.",
	"Go is a statically typed, compiled programming language designed at Google. It is syntactically similar to C, but with memory safety, garbage collection, structural typing, and CSP-style concurrency.",
	"Synthetic AI-detection benchmarks measure how effectively algorithms can distinguish between human-written and AI-generated content based on various linguistic and statistical patterns.",
}

// Add specific patterns that our AI detector might look for
var aiPatterns = []string{
	"As an AI language model, I can help you with that task.",
	"I'm sorry, but I cannot assist with that request.",
	"Based on my training data, I would say that...",
	"I don't have personal opinions, but I can provide information about...",
	"I don't have the ability to access external websites or databases.",
}

// Human writing patterns (distinct from typical AI outputs)
var humanPatterns = []string{
	"I strongly believe that this approach is superior, despite what others might say.",
	"This code is absolutely terrible! Who wrote this garbage?",
	"Honestly, I've been coding for 20 years and I've never seen anything like this before.",
	"Look, I don't care what the docs say - this is how we're going to do it.",
	"I hate to admit it, but I didn't understand half of what the speaker was saying.",
}

// Generate readable text of specified size using Lorem Ipsum paragraphs
func makeRandomBytes(size int) []byte {

	// Combine all our text sources
	allText := make([]string, 0, len(paragraphs)+len(aiPatterns)+len(humanPatterns))
	allText = append(allText, paragraphs...)
	allText = append(allText, aiPatterns...)
	allText = append(allText, humanPatterns...)

	// Generate content of requested size
	var builder strings.Builder
	builder.Grow(size)

	// Keep adding paragraphs with newlines until we reach or exceed the size
	for builder.Len() < size {
		idx := builder.Len() % len(allText)
		builder.WriteString(allText[idx])
		builder.WriteString("\n\n") // Add paragraph breaks
	}

	// Get the content and trim to the exact requested size
	content := builder.String()
	if len(content) > size {
		content = content[:size]
	}

	return []byte(content)
}

// Get the root directory for the package - ensures we're working in the right location
func getPackageRootDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename)
}

// Ensure benchmark data directory exists and has required files
func ensureBenchDataDir() string {
	pkgDir := getPackageRootDir()
	dir := filepath.Join(pkgDir, "testdata", "bench", "gen")

	benchDataInitOnce.Do(func() {
		// Create directory if it doesn't exist
		if err := os.MkdirAll(dir, 0755); err != nil {
			panic(fmt.Sprintf("Failed to create benchmark directory: %v", err))
		}

		// Check if we already have files
		entries, err := os.ReadDir(dir)
		if err == nil && len(entries) > 0 {
			return // Directory already has files
		}

		// Create 5000 files between 128-512 bytes in nested directories
		const totalFiles = 5000
		const maxDepth = 10

		fileExts := []string{".txt", ".md", ".go", ".py", ".js", ".html", ".css", ".json", ".yaml", ".xml"}

		for i := 0; i < totalFiles; i++ {
			// Generate a nested path like d01/d02/ with depth between 1-maxDepth
			depth := 1 + (i % maxDepth)
			var paths []string

			for d := 0; d < depth; d++ {
				dirNum := fmt.Sprintf("d%02d", (i+d)%100)
				paths = append(paths, dirNum)
			}

			// Add random file extension
			ext := fileExts[i%len(fileExts)]
			fileName := fmt.Sprintf("file%04d%s", i, ext)

			// Create full path
			fullPath := filepath.Join(append([]string{dir}, append(paths, fileName)...)...)

			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
				panic(fmt.Sprintf("Failed to create directory: %v", err))
			}

			// Generate random file size between 128-512 bytes
			size := 128 + (i % 385) // 128 to 512 bytes

			// Create content with some AI patterns
			data := makeRandomBytes(size)

			// Add AI patterns to some files
			if i%5 == 0 { // 20% of files have AI patterns
				patternIdx := i % len(aiPatterns)
				pattern := aiPatterns[patternIdx]

				// Only insert if pattern fits in file
				if len(pattern) < size {
					pos := size / 4 // Insert at 1/4 of the file
					copy(data[pos:], []byte(pattern))
				}
			}

			// Write the file
			if err := os.WriteFile(fullPath, data, 0644); err != nil {
				panic(fmt.Sprintf("Failed to write benchmark file %s: %v", fullPath, err))
			}
		}
	})

	return dir
}

// Safely redirect printUltra output to /dev/null for benchmarking
func benchPrintUltra(r Result) {
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

	// Print to the redirected stdout
	printUltra(r)

	// Restore stdout
	os.Stdout = old
}

// Helper function to create a result with n details for benchmarking
func makeResult(n int, smelly bool) Result {
	details := make(map[string]RuleHit, n)

	for i := 0; i < n; i++ {
		rule := Rule{
			Name:        fmt.Sprintf("rule-%d", i),
			Pattern:     fmt.Sprintf("pattern-%d", i),
			Weight:      10,
			Description: fmt.Sprintf("Description for rule %d", i),
		}

		details[rule.Name] = RuleHit{
			Rule:  rule,
			Count: i + 1,
		}
	}

	return Result{
		Path:   fmt.Sprintf("/path/to/file-%d.txt", n),
		Score:  n * 10, // 10 points per rule
		Detail: details,
		Smelly: smelly,
	}
}

// Generate a slice of results for benchmarking
func makeResults(count int) []Result {
	results := make([]Result, count)

	for i := range results {
		// Make some results smelly
		smelly := i%3 == 0
		detailCount := 1 + (i % 10) // 1-10 details per result
		results[i] = makeResult(detailCount, smelly)
	}

	return results
}
