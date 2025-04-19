package sniff

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// RuleHit stores hit count plus full rule metadata.
type RuleHit struct {
	Rule  Rule `json:"rule"`
	Count int  `json:"count"`
}

// Result is one file's outcome.
type Result struct {
	Path   string             `json:"path"`
	Score  int                `json:"score"`
	Detail map[string]RuleHit `json:"detail,omitempty"`
	Smelly bool               `json:"smelly"`
}

// Scan recursively walks each path and scores files.
//
// It returns a list of results sorted by path.
func Scan(roots []string, cfg Config) ([]Result, error) {
	rules, err := LoadRules(cfg.DictPath)
	if err != nil {
		return nil, err
	}
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
	}

	type job struct{ path string }
	jobs := make(chan job, cfg.Workers)
	out := make(chan Result, cfg.Workers)

	var wg sync.WaitGroup
	wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go func() {
			defer wg.Done()
			for j := range jobs {
				out <- analyse(j.path, rules, cfg)
			}
		}()
	}
	go func() { wg.Wait(); close(out) }()

	// Move directory walking into its own goroutine to prevent deadlock
	// This decouples job production from result consumption
	errCh := make(chan error, 1)
	dictPath := cfg.DictPath

	go func() {
		// Ensure jobs is closed on BOTH success and error paths
		defer close(jobs)

		for _, root := range roots {
			if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if d.IsDir() {
					if d.Name() == ".git" {
						return filepath.SkipDir
					}
					return nil
				}

				// Skip the dictionary file itself
				if dictPath != "" && filepath.Clean(p) == filepath.Clean(dictPath) {
					return nil
				}

				// Skip rule files by checking extension and content
				ext := strings.ToLower(filepath.Ext(p))
				if ext == ".yaml" || ext == ".yml" || ext == ".json" {
					// If it's a YAML/JSON file, check if it looks like a rules file
					data, err := os.ReadFile(p)
					if err == nil && len(data) > 0 {
						content := string(data)
						if strings.Contains(content, "pattern") && strings.Contains(content, "weight") {
							// Looks like a rules file, skip it
							return nil
						}
					}
				}

				jobs <- job{p}
				return nil
			}); err != nil {
				errCh <- err
				return
			}
		}
		// Signal successful completion
		errCh <- nil
	}()

	// Collect results as they arrive
	var results []Result
	for r := range out {
		results = append(results, r)
	}

	// Check if the directory walker encountered an error
	if err := <-errCh; err != nil {
		return nil, err
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Path < results[j].Path })
	return results, nil
}

func analyse(path string, rules []Rule, cfg Config) Result {
	// Skip if file doesn't exist, isn't a regular file, or exceeds size limit
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || (cfg.MaxSize > 0 && info.Size() > cfg.MaxSize) {
		return Result{Path: path}
	}

	// Read file content, skip if it's binary
	data, err := os.ReadFile(path)
	if err != nil || bytes.IndexByte(data, 0) != -1 {
		return Result{Path: path}
	}

	fileExt := filepath.Ext(path)
	score := 0
	detail := make(map[string]RuleHit)

	// Check each rule against the file content
	for _, r := range rules {
		// Skip rules that don't apply to this file extension
		if !r.appliesToExt(fileExt) {
			continue
		}

		// Count pattern occurrences
		count := bytes.Count(data, []byte(r.Pattern))

		// Skip patterns that don't match or don't pass thresholds
		if count == 0 || !r.passesThresholds(count, len(data)) {
			continue
		}

		// Calculate score and record hit
		ruleScore := count * r.Weight
		score += ruleScore
		detail[r.Name] = RuleHit{
			Rule:  r,
			Count: count,
		}
	}

	// Return the analysis result
	return Result{
		Path:   path,
		Score:  score,
		Detail: detail,
		Smelly: score >= cfg.Threshold,
	}
}
