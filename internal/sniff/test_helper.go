// Package sniff provides functionality to detect AI-generated text.
package sniff

import (
	"testing"
)

// setupTestPatterns creates special patterns for tests that match the rule patterns
// instead of actual Unicode characters which can be tricky to handle in tests.
func setupTestPatterns(t *testing.T) []Rule {
	t.Helper()

	// Create test rule patterns that exactly match test file contents
	// Add explicit patterns for tests rather than the actual Unicode patterns
	return []Rule{
		{
			Name:    "test-markdown-rule",
			Pattern: "\n---\n",
			Weight:  30,
			Ext:     ".md",
		},
		{
			Name:    "test-smart-quote",
			Pattern: "SMARTQUOTE",
			Weight:  10,
		},
		{
			Name:    "test-em-dash",
			Pattern: "EMDASH",
			// Keep weight at 3 to match TestAnalyse expectations
			Weight: 3,
		},
		{
			Name:    "custom-test-pattern",
			Pattern: "CUSTOM_PATTERN",
			Weight:  50,
		},
	}
}
