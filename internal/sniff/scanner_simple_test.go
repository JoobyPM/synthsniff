// Package sniff provides functionality to detect AI-generated text.
package sniff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanSimple verifies the core scanning functionality with a simple pattern
func TestScanSimple(t *testing.T) {
	// Create a temporary directory
	dir := t.TempDir()

	// Create two test files - one with the pattern, one without
	cleanFile := filepath.Join(dir, "clean.txt")
	require.NoError(t, os.WriteFile(cleanFile, []byte("This is a clean file"), 0644))

	smellyFile := filepath.Join(dir, "smelly.txt")
	require.NoError(t, os.WriteFile(smellyFile, []byte("This is a file with EXACT_TEST_PATTERN"), 0644))

	// Create a test dictionary file with a basic pattern
	dictFile := filepath.Join(dir, "dict.yaml")
	dictContent := `
- name: exact-pattern-test
  pattern: "EXACT_TEST_PATTERN"
  weight: 50
`
	require.NoError(t, os.WriteFile(dictFile, []byte(dictContent), 0644))

	// Create a test configuration with a reasonable MaxSize
	cfg := Config{
		DictPath:  dictFile,
		Threshold: 30,
		Workers:   1,
		MaxSize:   1 << 20, // 1MB should be more than enough
	}

	// Run the scan
	results, err := Scan([]string{dir}, cfg)
	require.NoError(t, err)

	// We should have two files
	assert.Equal(t, 2, len(results), "Expected 2 files (clean and smelly)")

	// Find the smelly file in the results
	var smellyResult *Result
	for i := range results {
		if strings.Contains(results[i].Path, "smelly.txt") {
			smellyResult = &results[i]
			break
		}
	}

	// Verify the smelly file was correctly identified
	require.NotNil(t, smellyResult, "Could not find smelly.txt in results")
	assert.True(t, smellyResult.Smelly, "Expected smelly.txt to be detected as smelly")
	assert.Equal(t, 50, smellyResult.Score, "Expected score to be 50")
	assert.NotNil(t, smellyResult.Detail, "Expected detail to be populated")
	assert.Contains(t, smellyResult.Detail, "exact-pattern-test", "Expected 'exact-pattern-test' pattern to be detected")
}

// TestAnalyseSimple verifies the basic pattern matching in analyse function
func TestAnalyseSimple(t *testing.T) {
	// Create a temporary directory
	dir := t.TempDir()

	// Create a simple file with our test pattern
	testFile := filepath.Join(dir, "test.txt")
	content := "This file contains EXACT_TEST_PATTERN for testing."
	require.NoError(t, os.WriteFile(testFile, []byte(content), 0644))

	// Create a simple rule
	rules := []Rule{
		{
			Name:    "exact-pattern-test",
			Pattern: "EXACT_TEST_PATTERN",
			Weight:  50,
		},
	}

	// Create a test with debug output
	content2 := string([]byte(content))
	pattern := string([]byte("EXACT_TEST_PATTERN"))
	
	t.Logf("Original content: %q", content)
	t.Logf("Bytes content: %q", content2)
	t.Logf("Pattern to search for: %q", pattern)
	t.Logf("Pattern bytes: % x", []byte(pattern))
	t.Logf("Content bytes: % x", []byte(content))
	
	// Check if pattern is in content
	isFound := strings.Contains(content, "EXACT_TEST_PATTERN")
	t.Logf("Pattern found with strings.Contains: %v", isFound)
	
	// Run the analyse function with MaxSize set
	result := analyse(testFile, rules, Config{
		Threshold: 30,
		MaxSize:   1 << 20, // 1MB should be enough
	})
	
	// Log the result details
	t.Logf("Result: smelly=%v, score=%d, details=%v", 
		result.Smelly, result.Score, result.Detail)

	// Verify the analysis results
	assert.True(t, result.Smelly, "File should be detected as smelly")
	assert.Equal(t, 50, result.Score, "Score should be 50")
	assert.Contains(t, result.Detail, "exact-pattern-test", "Should contain our test pattern")
}
