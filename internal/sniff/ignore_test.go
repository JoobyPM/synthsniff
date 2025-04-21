package sniff

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIgnoreRules(t *testing.T) {
	// Create a temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ignore-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	// Create test directory structure
	subDir := filepath.Join(tempDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	// Create parent .gitignore
	parentGitignore := filepath.Join(tempDir, ".gitignore")
	parentContent := "*.log\n"
	if err := os.WriteFile(parentGitignore, []byte(parentContent), 0644); err != nil {
		t.Fatalf("Failed to write parent gitignore: %v", err)
	}

	// Create child .gitignore that overrides parent
	childGitignore := filepath.Join(subDir, ".gitignore")
	childContent := "!important.log\n*.json\n"
	if err := os.WriteFile(childGitignore, []byte(childContent), 0644); err != nil {
		t.Fatalf("Failed to write child gitignore: %v", err)
	}

	// Create test files
	testFiles := []struct {
		path    string
		ignored bool
	}{
		{filepath.Join(tempDir, "test.txt"), false},
		{filepath.Join(tempDir, "test.log"), true},
		{filepath.Join(subDir, "normal.log"), true},
		{filepath.Join(subDir, "important.log"), false}, // Negated by child .gitignore
		{filepath.Join(subDir, "config.json"), true},    // Ignored by child .gitignore
	}

	for _, file := range testFiles {
		if err := os.WriteFile(file.path, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to write test file %s: %v", file.path, err)
		}
	}

	// Initialize ignore rules
	rules := NewIgnoreRules()

	// Reset the global variable before test
	LoadedIgnoreFiles = nil

	// Load both gitignore files
	if err := rules.FindAndLoadGitignores(tempDir); err != nil {
		t.Fatalf("Failed to load gitignore files: %v", err)
	}

	// Check if correct files were loaded
	if len(LoadedIgnoreFiles) != 2 {
		t.Errorf("Expected 2 loaded ignore files, got %d", len(LoadedIgnoreFiles))
	}

	// Test each file against the rules
	for _, file := range testFiles {
		// Ensure file exists
		if _, err := os.Stat(file.path); err != nil {
			t.Fatalf("Test file doesn't exist: %v", err)
		}

		// Get absolute paths for better logging
		absPath, err := filepath.Abs(file.path)
		if err != nil {
			t.Fatalf("Failed to get absolute path: %v", err)
		}

		// Test our ignore function
		ignored := rules.ShouldIgnore(file.path)
		if ignored != file.ignored {
			t.Logf("Directory structure:")
			t.Logf("  tempDir: %s", tempDir)
			t.Logf("  subDir: %s", subDir)
			t.Logf("  Testing file: %s", absPath)
			t.Logf("  patterns loaded: %v", rules.patterns)
			t.Errorf("File %s: expected ignored=%v, got %v", absPath, file.ignored, ignored)
		} else {
			t.Logf("File %s: correctly ignored=%v", absPath, ignored)
		}
	}
}
