package sniff

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// IgnorePattern represents a single pattern from a gitignore file
type IgnorePattern struct {
	Pattern   string
	Negate    bool // Pattern starts with !
	Directory bool // Pattern ends with /
	Root      bool // Pattern starts with /
}

// IgnoreRules stores the patterns from gitignore files
type IgnoreRules struct {
	mu       sync.RWMutex
	patterns map[string][]IgnorePattern // key is directory
}

// NewIgnoreRules creates a new IgnoreRules instance
func NewIgnoreRules() *IgnoreRules {
	return &IgnoreRules{
		patterns: make(map[string][]IgnorePattern),
	}
}

// LoadGitignoreFile loads a gitignore file and adds its patterns
func (r *IgnoreRules) LoadGitignoreFile(path string, baseDir string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to close gitignore file: %v\n", err)
		}
	}()

	r.mu.Lock()
	defer r.mu.Unlock()

	patterns := []IgnorePattern{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		pattern := IgnorePattern{}
		// Handle negation
		if strings.HasPrefix(line, "!") {
			pattern.Negate = true
			line = line[1:]
		}

		// Handle patterns that are anchored to the root
		if strings.HasPrefix(line, "/") {
			pattern.Root = true
			line = line[1:]
		}

		// Handle directory-specific patterns
		if strings.HasSuffix(line, "/") {
			pattern.Directory = true
			line = line[:len(line)-1]
		}

		pattern.Pattern = line
		patterns = append(patterns, pattern)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// Store patterns for this directory
	r.patterns[baseDir] = append(r.patterns[baseDir], patterns...)

	return nil
}

// LoadCustomIgnoreFile loads a custom ignore file
func (r *IgnoreRules) LoadCustomIgnoreFile(path string) error {
	baseDir := filepath.Dir(path)
	return r.LoadGitignoreFile(path, baseDir)
}

// ShouldIgnore checks if a file should be ignored
func (r *IgnoreRules) ShouldIgnore(filePath string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Normalize path
	filePath = filepath.Clean(filePath)
	fileName := filepath.Base(filePath)
	isDir := false

	// Check if the path is a directory
	fileInfo, err := os.Stat(filePath)
	if err == nil && fileInfo.IsDir() {
		isDir = true
	}

	// Find all parent directories that might have .gitignore files
	dir := filepath.Dir(filePath)
	var relevantDirs []string

	// Start with immediate directory and go up
	for dir != "" && dir != "." && dir != "/" {
		relevantDirs = append(relevantDirs, dir)
		parentDir := filepath.Dir(dir)
		if parentDir == dir {
			break
		}
		dir = parentDir
	}

	// Add "." as a fallback
	relevantDirs = append(relevantDirs, ".")

	// Reverse the array to check patterns from root to leaf (parent dirs first)
	for i, j := 0, len(relevantDirs)-1; i < j; i, j = i+1, j-1 {
		relevantDirs[i], relevantDirs[j] = relevantDirs[j], relevantDirs[i]
	}

	// Track whether the file should be ignored
	ignored := false

	// Check patterns in each relevant directory
	for _, dir := range relevantDirs {
		if patterns, ok := r.patterns[dir]; ok {
			for _, pattern := range patterns {
				// Skip directory patterns if we're checking a file
				if pattern.Directory && !isDir {
					continue
				}

				// Get the relative path from the gitignore directory
				relPath, err := filepath.Rel(dir, filePath)
				if err != nil {
					// If we can't get a relative path, just use the filename
					relPath = fileName
				}

				match := false

				// Match based on pattern type
				if pattern.Root {
					// Anchored pattern - must match from the directory containing the gitignore
					pathToMatch := relPath
					if filepath.IsAbs(pathToMatch) {
						pathToMatch = pathToMatch[1:] // Remove leading slash if present
					}
					match = matchGlob(pattern.Pattern, pathToMatch)
				} else {
					// Non-anchored pattern - can match anywhere in the path
					// For files, just check the filename
					if isDir {
						match = matchGlob(pattern.Pattern, relPath) || matchGlob(pattern.Pattern, fileName)
					} else {
						match = matchGlob(pattern.Pattern, fileName)
					}
				}

				if match {
					// Negation flips the current state
					if pattern.Negate {
						ignored = false
					} else {
						ignored = true
					}
				}
			}
		}
	}

	return ignored
}

// matchGlob provides pattern matching for gitignore patterns
// This is an improved implementation for handling glob patterns
func matchGlob(pattern, name string) bool {
	// Direct match
	if pattern == name {
		return true
	}

	// Handle simple * glob (matches any string)
	if strings.Contains(pattern, "*") {
		// Convert gitignore glob pattern to Go's filepath.Match pattern
		// but we need to be careful because they have slight differences

		// For now, let's handle the most common patterns

		// Pattern with single * (e.g., "*.txt", "log/*", "src/*.go")
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			// Pattern like "*.txt"
			if parts[0] == "" && parts[1] != "" {
				return strings.HasSuffix(name, parts[1])
			}

			// Pattern like "log/*"
			if parts[0] != "" && parts[1] == "" {
				return strings.HasPrefix(name, parts[0])
			}

			// Pattern like "src/*.go"
			if parts[0] != "" && parts[1] != "" {
				return strings.HasPrefix(name, parts[0]) && strings.HasSuffix(name, parts[1])
			}
		}

		// More complex patterns with multiple *
		if len(parts) > 2 {
			// Try to match all parts in order
			pos := 0
			for i, part := range parts {
				if part == "" {
					continue // Skip empty parts (adjacent *)
				}

				// For first part, check prefix
				if i == 0 {
					if !strings.HasPrefix(name, part) {
						return false
					}
					pos = len(part)
					continue
				}

				// For last part, check suffix
				if i == len(parts)-1 {
					return strings.HasSuffix(name, part)
				}

				// For middle parts, find position after current position
				idx := strings.Index(name[pos:], part)
				if idx == -1 {
					return false
				}
				pos += idx + len(part)
			}
			return true
		}
	}

	// Use filepath.Match for simple wildcard patterns
	matched, _ := filepath.Match(pattern, name)
	return matched
}

// FindAndLoadGitignores recursively scans directories and loads .gitignore files
func (r *IgnoreRules) FindAndLoadGitignores(rootDir string) error {
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the .git directory
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}

		// Look for .gitignore files
		if info.Name() == ".gitignore" {
			baseDir := filepath.Dir(path)
			if err := r.LoadGitignoreFile(path, baseDir); err != nil {
				return err
			}

			// Record loaded gitignore for reporting using global variable
			LoadedIgnoreFiles = append(LoadedIgnoreFiles, path)
		}

		return nil
	})

	return err
}
