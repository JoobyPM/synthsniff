package sniff

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
	go func() {
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
				jobs <- job{p}
				return nil
			}); err != nil {
				errCh <- err
				return
			}
		}
		close(jobs)
		errCh <- nil // Signal successful completion
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
	// Debug: Log the input parameters
	fmt.Printf("[analyse debug] path=%q, rules=%d, threshold=%d\n", 
		path, len(rules), cfg.Threshold)
	
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > cfg.MaxSize {
		fmt.Printf("[analyse debug] Early return: err=%v, isRegular=%v, size=%d, maxSize=%d\n",
			err, info != nil && info.Mode().IsRegular(), info.Size(), cfg.MaxSize)
		return Result{Path: path}
	}

	data, err := os.ReadFile(path)
	if err != nil || bytes.IndexByte(data, 0) != -1 {
		fmt.Printf("[analyse debug] Read error or binary file: err=%v, hasBinary=%v\n", 
			err, bytes.IndexByte(data, 0) != -1)
		return Result{Path: path}
	}

	fileExt := filepath.Ext(path)
	score := 0
	detail := make(map[string]RuleHit)

	fmt.Printf("[analyse debug] Checking %d rules for ext=%q\n", len(rules), fileExt)
	for i, r := range rules {
		fmt.Printf("[analyse debug] Rule %d: name=%q, pattern=%q\n", i, r.Name, r.Pattern)
		
		if !r.appliesToExt(fileExt) {
			fmt.Printf("[analyse debug] Rule does not apply to ext %q\n", fileExt)
			continue
		}
		count := bytes.Count(data, []byte(r.Pattern))
		fmt.Printf("[analyse debug] Pattern count: %d\n", count)
		
		if count == 0 || !r.passesThresholds(count, len(data)) {
			fmt.Printf("[analyse debug] Skip: count=%d, passesThreshold=%v\n", 
				count, count != 0 && r.passesThresholds(count, len(data)))
			continue
		}
		
		score += count * r.Weight
		detail[r.Name] = RuleHit{Rule: r, Count: count}
		fmt.Printf("[analyse debug] Added score: %d, total now: %d\n", count*r.Weight, score)
	}

	result := Result{
		Path:   path,
		Score:  score,
		Detail: detail,
		Smelly: score >= cfg.Threshold,
	}
	
	fmt.Printf("[analyse debug] Final result: score=%d, smelly=%v, details=%v\n", 
		score, score >= cfg.Threshold, detail)
	
	return result
}
