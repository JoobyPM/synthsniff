// Package sniff provides functionality to detect AI-generated text.
package sniff

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDebugAnalyse takes a detailed look at each step of the analyse function
func TestDebugAnalyse(t *testing.T) {
	// Create a file with a test pattern
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	content := "This file contains EXACT_TEST_PATTERN for testing."
	require.NoError(t, os.WriteFile(testFile, []byte(content), 0644))

	// Define rules
	rules := []Rule{
		{
			Name:    "test-rule",
			Pattern: "EXACT_TEST_PATTERN",
			Weight:  50,
		},
	}

	// Define config with MaxSize
	cfg := Config{
		Threshold: 30,
		MaxSize:   1 << 20, // 1MB
	}

	// Step 1: Stat the file (same as analyse function)
	info, err := os.Stat(testFile)
	require.NoError(t, err)
	t.Logf("File info: size=%d, regular=%v", info.Size(), info.Mode().IsRegular())
	assert.True(t, info.Mode().IsRegular(), "File should be regular")
	assert.Less(t, int64(0), info.Size(), "File size should be greater than 0")

	// Step 2: Read the file contents (same as analyse function)
	data, err := os.ReadFile(testFile)
	require.NoError(t, err)
	t.Logf("File content: %q", string(data))
	assert.Contains(t, string(data), "EXACT_TEST_PATTERN", "File should contain our pattern")

	// Step 3: Check for binary file (same as analyse function)
	hasBinaryByte := bytes.IndexByte(data, 0) != -1
	t.Logf("Has binary byte: %v", hasBinaryByte)
	assert.False(t, hasBinaryByte, "File should not have binary bytes")

	// Step 4: Get file extension (same as analyse function)
	fileExt := filepath.Ext(testFile)
	t.Logf("File extension: %q", fileExt)

	// Step 5: Iterate through rules and check for matches
	foundSmelly := false
	totalScore := 0

	for _, r := range rules {
		t.Logf("Checking rule %q with pattern %q", r.Name, r.Pattern)

		// Step 5a: Check if rule applies to this extension
		applies := r.appliesToExt(fileExt)
		t.Logf("  Rule applies to extension %q: %v", fileExt, applies)

		if !applies {
			t.Logf("  Rule does not apply to this extension, skipping")
			continue
		}

		// Step 5b: Count pattern matches
		patternBytes := []byte(r.Pattern)
		contentBytes := data

		t.Logf("  Pattern bytes: % x", patternBytes)
		t.Logf("  Content first 50 bytes: % x", contentBytes[:min(50, len(contentBytes))])

		count := bytes.Count(contentBytes, patternBytes)
		t.Logf("  Pattern count: %d", count)

		if count == 0 {
			t.Logf("  Pattern not found, skipping")
			continue
		}

		// Step 5c: Check thresholds
		passes := r.passesThresholds(count, len(contentBytes))
		t.Logf("  Rule passes thresholds: %v", passes)

		if !passes {
			t.Logf("  Rule doesn't pass threshold requirements, skipping")
			continue
		}

		// Step 5d: Calculate score
		score := count * r.Weight
		t.Logf("  Adding to score: %d * %d = %d", count, r.Weight, score)
		totalScore += score
	}

	// Step 6: Check if file is smelly
	foundSmelly = totalScore >= cfg.Threshold
	t.Logf("Final score: %d, threshold: %d, smelly: %v", totalScore, cfg.Threshold, foundSmelly)

	// Step 7: Verify result matches expectations
	assert.True(t, foundSmelly, "File should be marked as smelly")
	assert.Equal(t, 50, totalScore, "Score should be 50")

	// Step 8: Compare with the actual analyse function
	actualResult := analyse(testFile, rules, cfg)
	t.Logf("Actual analyse result: smelly=%v, score=%d, details=%v",
		actualResult.Smelly, actualResult.Score, actualResult.Detail)

	assert.Equal(t, foundSmelly, actualResult.Smelly, "Manual and actual Smelly should match")
	assert.Equal(t, totalScore, actualResult.Score, "Manual and actual Score should match")
}

// Helper to find minimum of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
