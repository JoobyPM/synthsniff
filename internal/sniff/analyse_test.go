// Package sniff provides functionality to detect AI-generated text.
package sniff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSimpleAnalyse tests the core analysis functionality with simplified patterns
func TestSimpleAnalyse(t *testing.T) {
	// Create a temporary test directory
	tempDir := t.TempDir()

	// Create a test file with a simple pattern we can detect
	testContent := "This file contains TEST_PATTERN_MARKER"
	testFile := filepath.Join(tempDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte(testContent), 0644))

	// Create a simple rule set with just one rule that matches our test file
	rules := []Rule{
		{
			Name:    "test-rule",
			Pattern: "TEST_PATTERN_MARKER",
			Weight:  50,
		},
	}

	// Test with a threshold lower than the rule weight (should be smelly)
	lowThresholdCfg := Config{Threshold: 30}
	result := analyse(testFile, rules, lowThresholdCfg)
	
	// Verify the file is detected as smelly
	assert.True(t, result.Smelly, "File should be detected as smelly with low threshold")
	assert.Equal(t, 50, result.Score, "Score should match the rule weight")
	assert.Equal(t, 1, len(result.Detail), "Should have one rule match")
	assert.Contains(t, result.Detail, "test-rule", "Should contain our test rule")

	// Test with a threshold higher than the rule weight (should not be smelly)
	highThresholdCfg := Config{Threshold: 60}
	result = analyse(testFile, rules, highThresholdCfg)
	
	// Verify the file is not detected as smelly due to high threshold
	assert.False(t, result.Smelly, "File should not be detected as smelly with high threshold")
	assert.Equal(t, 50, result.Score, "Score should still match the rule weight")
	assert.Equal(t, 1, len(result.Detail), "Should still have one rule match")
}

// TestSimpleScan tests the scanning functionality with simplified patterns
func TestSimpleScan(t *testing.T) {
	// Create a temporary test directory
	tempDir := t.TempDir()

	// Create a clean file (no patterns)
	cleanFile := filepath.Join(tempDir, "clean.txt")
	require.NoError(t, os.WriteFile(cleanFile, []byte("This is a clean file."), 0644))

	// Create a file with our test pattern
	smellyFile := filepath.Join(tempDir, "smelly.txt")
	require.NoError(t, os.WriteFile(smellyFile, []byte("This file has TEST_PATTERN_MARKER"), 0644))

	// Create a dictionary file with our test pattern
	dictFile := filepath.Join(tempDir, "rules.yaml")
	dictContent := `
- name: test-rule
  pattern: "TEST_PATTERN_MARKER"
  weight: 50
`
	require.NoError(t, os.WriteFile(dictFile, []byte(dictContent), 0644))

	// Run a scan with our test dictionary
	results, err := Scan([]string{tempDir}, Config{
		Threshold: 30,
		DictPath:  dictFile,
		Workers:   1,
	})

	// Verify scan results
	require.NoError(t, err)
	assert.Equal(t, 2, len(results), "Should have results for both files")

	// Count smelly files
	smellyCount := 0
	for _, r := range results {
		if r.Smelly {
			smellyCount++
			assert.Contains(t, r.Path, "smelly.txt", "Smelly file should be the one with our test pattern")
		}
	}
	assert.Equal(t, 1, smellyCount, "Should detect exactly one smelly file")
}

// TestCustomRuleAnalyse tests specifically the custom pattern functionality
func TestCustomRuleAnalyse(t *testing.T) {
	// Create a temporary test directory
	tempDir := t.TempDir()

	// Create a test file with a custom pattern
	testFile := filepath.Join(tempDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("This file contains CUSTOM_PATTERN"), 0644))

	// Create a rule that matches our custom pattern
	rules := []Rule{
		{
			Name:    "custom-rule",
			Pattern: "CUSTOM_PATTERN",
			Weight:  50,
		},
	}

	// Test with the custom rule
	result := analyse(testFile, rules, Config{Threshold: 30})
	
	// Verify custom rule detection
	assert.True(t, result.Smelly, "File should be detected as smelly with custom rule")
	assert.Equal(t, 50, result.Score, "Score should match the custom rule weight")
	assert.Contains(t, result.Detail, "custom-rule", "Should detect the custom rule")
}
