// Package sniff provides functionality to detect AI-generated text.
package sniff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadRules verifies loading rule dictionaries from different sources.
func TestLoadRules(t *testing.T) {
	// Create a temporary JSON dictionary file
	jsonDict := `[
		{
			"name": "test-json",
			"pattern": "test-pattern",
			"weight": 5
		}
	]`
	jsonFile := filepath.Join(t.TempDir(), "rules.json")
	require.NoError(t, os.WriteFile(jsonFile, []byte(jsonDict), 0644))

	// Create a temporary YAML dictionary file
	yamlDict := `- name: test-yaml
  pattern: test-pattern
  weight: 5`
	yamlFile := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(yamlFile, []byte(yamlDict), 0644))

	// Create an invalid file
	invalidFile := filepath.Join(t.TempDir(), "invalid.txt")
	require.NoError(t, os.WriteFile(invalidFile, []byte("not json or yaml"), 0644))

	tests := []struct {
		name      string
		dictPath  string
		wantErr   bool
		wantRules int // Total rules count (base + custom)
	}{
		{
			name:      "defaults only",
			dictPath:  "",
			wantErr:   false,
			wantRules: len(baseRules),
		},
		{
			name:      "json dictionary",
			dictPath:  jsonFile,
			wantErr:   false,
			wantRules: len(baseRules) + 1,
		},
		{
			name:      "yaml dictionary",
			dictPath:  yamlFile,
			wantErr:   false,
			wantRules: len(baseRules) + 1,
		},
		{
			name:      "file not found",
			dictPath:  "nonexistent.json",
			wantErr:   true,
			wantRules: 0,
		},
		{
			name:      "invalid format",
			dictPath:  invalidFile,
			wantErr:   true,
			wantRules: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := LoadRules(tt.dictPath)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, rules, tt.wantRules)

				if tt.dictPath == jsonFile {
					// Check that our custom rule was appended
					found := false
					for _, r := range rules {
						if r.Name == "test-json" {
							found = true
							assert.Equal(t, "test-pattern", r.Pattern)
							assert.Equal(t, 5, r.Weight)
							break
						}
					}
					assert.True(t, found, "Custom JSON rule not found")
				}

				if tt.dictPath == yamlFile {
					// Check that our custom rule was appended
					found := false
					for _, r := range rules {
						if r.Name == "test-yaml" {
							found = true
							assert.Equal(t, "test-pattern", r.Pattern)
							assert.Equal(t, 5, r.Weight)
							break
						}
					}
					assert.True(t, found, "Custom YAML rule not found")
				}
			}
		})
	}
}

// TestRuleAppliesToExt verifies the extension matching logic.
func TestRuleAppliesToExt(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		ext      string
		expected bool
	}{
		{
			name:     "no extension restriction",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1},
			ext:      ".md",
			expected: true,
		},
		{
			name:     "matching single extension",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, Ext: ".md"},
			ext:      ".md",
			expected: true,
		},
		{
			name:     "non-matching single extension",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, Ext: ".md"},
			ext:      ".txt",
			expected: false,
		},
		{
			name:     "matching extension in list",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, Exts: []string{".md", ".txt"}},
			ext:      ".txt",
			expected: true,
		},
		{
			name:     "non-matching extension in list",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, Exts: []string{".md", ".txt"}},
			ext:      ".go",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.appliesToExt(tt.ext)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRulePassesThresholds verifies the threshold validation logic.
func TestRulePassesThresholds(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		count    int
		fileLen  int
		expected bool
	}{
		{
			name:     "no thresholds",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1},
			count:    1,
			fileLen:  100,
			expected: true,
		},
		{
			name:     "minCount satisfied",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, MinCount: 3},
			count:    5,
			fileLen:  100,
			expected: true,
		},
		{
			name:     "minCount not satisfied",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, MinCount: 3},
			count:    2,
			fileLen:  100,
			expected: false,
		},
		{
			name:     "minPercent satisfied",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, MinPercent: 2.0},
			count:    3,
			fileLen:  100, // 3/100 = 3% > 2%
			expected: true,
		},
		{
			name:     "minPercent not satisfied",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, MinPercent: 2.0},
			count:    1,
			fileLen:  100, // 1/100 = 1% < 2%
			expected: false,
		},
		{
			name:     "both thresholds satisfied",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, MinCount: 3, MinPercent: 2.0},
			count:    5,
			fileLen:  100, // 5/100 = 5% > 2%
			expected: true,
		},
		{
			name:     "minCount satisfied but minPercent not",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, MinCount: 3, MinPercent: 10.0},
			count:    5,
			fileLen:  100, // 5/100 = 5% < 10%
			expected: false,
		},
		{
			name:     "minPercent satisfied but minCount not",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, MinCount: 10, MinPercent: 2.0},
			count:    5,
			fileLen:  100, // 5/100 = 5% > 2%
			expected: false,
		},
		{
			name:     "zero file length with minPercent",
			rule:     Rule{Name: "test", Pattern: "pattern", Weight: 1, MinPercent: 2.0},
			count:    1,
			fileLen:  0,
			expected: true, // Avoid division by zero
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.passesThresholds(tt.count, tt.fileLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRelPathExt verifies the extension extraction helper.
func TestRelPathExt(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "markdown file",
			path:     "file.md",
			expected: ".md",
		},
		{
			name:     "golang file",
			path:     "file.go",
			expected: ".go",
		},
		{
			name:     "no extension",
			path:     "file",
			expected: "",
		},
		{
			name:     "multiple dots",
			path:     "file.tar.gz",
			expected: ".gz",
		},
		{
			name:     "path with directories",
			path:     "path/to/file.txt",
			expected: ".txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RelPathExt(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}
