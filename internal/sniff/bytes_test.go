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

// TestBytesCount directly tests the underlying bytes.Count function
func TestBytesCount(t *testing.T) {
	// Create a file with our test pattern
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	content := "This file contains EXACT_TEST_PATTERN for testing."
	require.NoError(t, os.WriteFile(testFile, []byte(content), 0644))

	// Read the file to make sure we have the same bytes
	data, err := os.ReadFile(testFile)
	require.NoError(t, err)

	// Directly test bytes.Count which is used by analyse
	pattern := []byte("EXACT_TEST_PATTERN")
	count := bytes.Count(data, pattern)

	// Log details for debugging
	t.Logf("Content: %q", data)
	t.Logf("Pattern: %q", pattern)
	t.Logf("Count: %d", count)

	// This should be 1
	assert.Equal(t, 1, count, "bytes.Count should find the pattern")

	// Let's also directly inspect the analyse function's logic
	fileExt := filepath.Ext(testFile)
	t.Logf("File extension: %q", fileExt)

	// Create a rule that should match
	rule := Rule{
		Name:    "test-rule",
		Pattern: "EXACT_TEST_PATTERN",
		Weight:  50,
	}

	// Check if rule applies to extension
	applies := rule.appliesToExt(fileExt)
	t.Logf("Rule applies to extension: %v", applies)

	// Check threshold logic
	passes := rule.passesThresholds(count, len(data))
	t.Logf("Rule passes thresholds: %v", passes)

	// Now manually recreate the analyse function logic
	score := 0
	if applies && count > 0 && passes {
		score = count * rule.Weight
		t.Logf("Score calculated: %d", score)
	} else {
		t.Logf("No score: applies=%v, count=%d, passes=%v", applies, count, passes)
	}

	assert.Equal(t, 50, score, "Score should be calculated correctly")
}
