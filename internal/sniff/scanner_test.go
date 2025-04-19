// Package sniff provides functionality to detect AI-generated text.
package sniff

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAnalyse verifies the file analysis logic.
func TestAnalyse(t *testing.T) {
	// Skip this test when running with -short flag
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Create a temporary test directory
	tempDir := t.TempDir()

	// Set up test files
	cleanFile := filepath.Join(tempDir, "clean.txt")
	require.NoError(t, os.WriteFile(cleanFile, []byte("This is a clean file with no AI patterns."), 0644))

	// Create a markdown file with test patterns that will match our custom rules
	smellyContent := "This file has SMARTQUOTE and EMDASH patterns.\n---\nAnd Markdown rules."
	smellyFile := filepath.Join(tempDir, "smelly.md")
	require.NoError(t, os.WriteFile(smellyFile, []byte(smellyContent), 0644))

	binaryFile := filepath.Join(tempDir, "binary.bin")
	require.NoError(t, os.WriteFile(binaryFile, []byte{0x00, 0x01, 0x02, 0x03}, 0644))

	// Create a directory
	dirPath := filepath.Join(tempDir, "subdir")
	require.NoError(t, os.Mkdir(dirPath, 0755))

	// Use our test patterns that match the file content
	rules := setupTestPatterns(t)

	tests := []struct {
		name       string
		path       string
		cfg        Config
		wantSmelly bool
		wantScore  int
		wantDetail int // Number of detail entries expected
	}{
		{
			name:       "clean file",
			path:       cleanFile,
			cfg:        Config{Threshold: 30},
			wantSmelly: false,
			wantScore:  0,
			wantDetail: 0,
		},
		{
			name:       "smelly file with low threshold",
			path:       smellyFile,
			cfg:        Config{Threshold: 30},
			wantSmelly: true,
			wantScore:  43, // markdown rule (30) + em dash (3) + smart quotes (10)
			wantDetail: 3,
		},
		{
			name:       "smelly file with high threshold",
			path:       smellyFile,
			cfg:        Config{Threshold: 100},
			wantSmelly: false,
			wantScore:  43, // markdown rule (30) + em dash (3) + smart quotes (10)
			wantDetail: 3,
		},
		{
			name:       "binary file",
			path:       binaryFile,
			cfg:        Config{Threshold: 30},
			wantSmelly: false,
			wantScore:  0,
			wantDetail: 0,
		},
		{
			name:       "directory",
			path:       dirPath,
			cfg:        Config{Threshold: 30},
			wantSmelly: false,
			wantScore:  0,
			wantDetail: 0,
		},
		{
			name:       "non-existent file",
			path:       filepath.Join(tempDir, "nonexistent.txt"),
			cfg:        Config{Threshold: 30},
			wantSmelly: false,
			wantScore:  0,
			wantDetail: 0,
		},
		{
			name:       "size limit",
			path:       cleanFile,
			cfg:        Config{Threshold: 30, MaxSize: 1}, // 1 byte size limit
			wantSmelly: false,
			wantScore:  0,
			wantDetail: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyse(tt.path, rules, tt.cfg)

			assert.Equal(t, tt.path, result.Path)
			assert.Equal(t, tt.wantSmelly, result.Smelly)
			assert.Equal(t, tt.wantScore, result.Score)
			assert.Equal(t, tt.wantDetail, len(result.Detail))
		})
	}
}

// TestScan verifies the directory scanning functionality.
func TestScan(t *testing.T) {
	// Skip test in short mode
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Create a temporary test directory structure
	tempDir := t.TempDir()

	// Create clean and smelly files in root
	require.NoError(t, os.WriteFile(
		filepath.Join(tempDir, "clean.txt"),
		[]byte("This is a clean file with no AI patterns."),
		0644))

	// Create a markdown file with test patterns
	smellyContent := "This file has SMARTQUOTE and EMDASH also with Markdown.\n---\nFeatures."
	require.NoError(t, os.WriteFile(
		filepath.Join(tempDir, "smelly.md"),
		[]byte(smellyContent),
		0644))

	// Create subdirectory
	subDir := filepath.Join(tempDir, "subdir")
	require.NoError(t, os.Mkdir(subDir, 0755))

	// Create a file in subdirectory with em-dash
	subfileContent := "This file has EMDASH in a subdirectory."
	require.NoError(t, os.WriteFile(
		filepath.Join(subDir, "subfile.md"),
		[]byte(subfileContent),
		0644))

	// Create .git directory (should be ignored)
	gitDir := filepath.Join(tempDir, ".git")
	require.NoError(t, os.Mkdir(gitDir, 0755))

	// Create a file in .git directory (should be ignored)
	require.NoError(t, os.WriteFile(
		filepath.Join(gitDir, "gitfile.txt"),
		[]byte("This file should be ignored."),
		0644))

	tests := []struct {
		name        string
		roots       []string
		cfg         Config
		wantErr     bool
		wantLen     int
		wantSmelly  int
		wantSkipped int // Skipped paths (.git, etc.)
	}{
		{
			name:       "scan root",
			roots:      []string{tempDir},
			cfg:        Config{Threshold: 30, Workers: runtime.NumCPU()},
			wantErr:    false,
			wantLen:    3, // clean.txt, smelly.md, subdir/subfile.md
			wantSmelly: 2, // smelly.md, subdir/subfile.md
		},
		{
			name:       "scan subdirectory only",
			roots:      []string{subDir},
			cfg:        Config{Threshold: 30, Workers: runtime.NumCPU()},
			wantErr:    false,
			wantLen:    1, // subdir/subfile.md
			wantSmelly: 1, // subdir/subfile.md
		},
		{
			name:       "non-existent directory",
			roots:      []string{filepath.Join(tempDir, "nonexistent")},
			cfg:        Config{Threshold: 30, Workers: runtime.NumCPU()},
			wantErr:    true,
			wantLen:    0,
			wantSmelly: 0,
		},
		{
			name:       "multiple roots",
			roots:      []string{filepath.Join(tempDir, "clean.txt"), subDir},
			cfg:        Config{Threshold: 30, Workers: runtime.NumCPU()},
			wantErr:    false,
			wantLen:    2, // clean.txt, subdir/subfile.md
			wantSmelly: 1, // subdir/subfile.md
		},
		{
			name:       "high threshold",
			roots:      []string{tempDir},
			cfg:        Config{Threshold: 100, Workers: runtime.NumCPU()},
			wantErr:    false,
			wantLen:    3, // clean.txt, smelly.md, subdir/subfile.md
			wantSmelly: 0, // none exceed high threshold
		},
		{
			name:       "single worker",
			roots:      []string{tempDir},
			cfg:        Config{Threshold: 30, Workers: 1},
			wantErr:    false,
			wantLen:    3, // clean.txt, smelly.md, subdir/subfile.md
			wantSmelly: 2, // smelly.md, subdir/subfile.md
		},
		{
			name:       "zero workers",
			roots:      []string{tempDir},
			cfg:        Config{Threshold: 30, Workers: 0}, // Testing the Workers <= 0 case
			wantErr:    false,
			wantLen:    3, // clean.txt, smelly.md, subdir/subfile.md
			wantSmelly: 2, // smelly.md, subdir/subfile.md
		},
		{
			name:       "negative workers",
			roots:      []string{tempDir},
			cfg:        Config{Threshold: 30, Workers: -1}, // Testing the Workers <= 0 case
			wantErr:    false,
			wantLen:    3, // clean.txt, smelly.md, subdir/subfile.md
			wantSmelly: 2, // smelly.md, subdir/subfile.md
		},
	}

	// Create a test dictionary file for regular tests with a higher weight for EMDASH
	// to ensure files with EMDASH in subdirectories are detected as smelly
	regDict := filepath.Join(tempDir, "reg_dict.yaml")
	regDictContent := `
- name: test-markdown-rule
  pattern: "\n---\n"
  weight: 30
  ext: ".md"
- name: test-smart-quote
  pattern: "SMARTQUOTE"
  weight: 10
- name: test-em-dash
  pattern: "EMDASH"
  weight: 30
- name: custom-test-pattern
  pattern: "CUSTOM_PATTERN"
  weight: 50`
	require.NoError(t, os.WriteFile(regDict, []byte(regDictContent), 0644))

	// Create a test dictionary file for high threshold test
	highDict := filepath.Join(tempDir, "high_dict.yaml")
	highDictContent := `
- name: test-markdown-rule
  pattern: "\n---\n"
  weight: 30
  ext: ".md"
- name: test-smart-quote
  pattern: "SMARTQUOTE"
  weight: 10
- name: test-em-dash
  pattern: "EMDASH"
  weight: 3
- name: custom-test-pattern
  pattern: "CUSTOM_PATTERN"
  weight: 50`
	require.NoError(t, os.WriteFile(highDict, []byte(highDictContent), 0644))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Choose the appropriate dictionary for the test
			if tt.name == "high threshold" {
				tt.cfg.DictPath = highDict
			} else {
				tt.cfg.DictPath = regDict
			}

			results, err := Scan(tt.roots, tt.cfg)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantLen, len(results), "Should return expected number of results")

				// Count smelly files
				smellyCount := 0
				for _, r := range results {
					if r.Smelly {
						smellyCount++
					}
				}
				assert.Equal(t, tt.wantSmelly, smellyCount, "Should identify correct number of smelly files")

				// Verify results are sorted by path
				assert.True(t, sort.SliceIsSorted(results, func(i, j int) bool {
					return results[i].Path < results[j].Path
				}), "Results should be sorted by path")
			}
		})
	}
}

// TestScanInvalidDict verifies Scan behavior with invalid dictionaries.
func TestScanInvalidDict(t *testing.T) {
	// Create a temporary directory
	tempDir := t.TempDir()

	// Create an invalid dictionary file
	invalidDict := filepath.Join(tempDir, "invalid.dict")
	require.NoError(t, os.WriteFile(invalidDict, []byte("not json or yaml"), 0644))

	// Test with invalid dictionary
	_, err := Scan([]string{tempDir}, Config{DictPath: invalidDict})
	assert.Error(t, err, "Scan should return error with invalid dictionary")

	// Test with non-existent dictionary
	_, err = Scan([]string{tempDir}, Config{DictPath: "nonexistent.dict"})
	assert.Error(t, err, "Scan should return error with non-existent dictionary")
}

// TestAnalyseWithCustomRules verifies analysis with custom rule dictionaries.
func TestAnalyseWithCustomRules(t *testing.T) {
	// Create a temporary directory
	tempDir := t.TempDir()

	// Create a test file
	testFile := filepath.Join(tempDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("This file contains a custom pattern: CUSTOM_PATTERN"), 0644))

	// Use test patterns directly instead of loading from file
	rules := setupTestPatterns(t)

	// Test with custom rules
	result := analyse(testFile, rules, Config{Threshold: 30})
	assert.True(t, result.Smelly, "File should be detected as smelly with custom rule")
	assert.GreaterOrEqual(t, result.Score, 50, "Score should include custom rule weight")
	assert.Contains(t, result.Detail, "custom-test-pattern", "Detail should include custom rule")
}
