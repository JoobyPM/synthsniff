package sniff

import (
	"bytes"
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
			return nil, err
		}
	}
	close(jobs)

	var results []Result
	for r := range out {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Path < results[j].Path })
	return results, nil
}

func analyse(path string, rules []Rule, cfg Config) Result {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > cfg.MaxSize {
		return Result{Path: path}
	}

	data, err := os.ReadFile(path)
	if err != nil || bytes.IndexByte(data, 0) != -1 {
		return Result{Path: path}
	}

	fileExt := filepath.Ext(path)
	score := 0
	detail := make(map[string]RuleHit)

	for _, r := range rules {
		if !r.appliesToExt(fileExt) {
			continue
		}
		count := bytes.Count(data, []byte(r.Pattern))
		if count == 0 || !r.passesThresholds(count, len(data)) {
			continue
		}
		score += count * r.Weight
		detail[r.Name] = RuleHit{Rule: r, Count: count}
	}

	return Result{
		Path:   path,
		Score:  score,
		Detail: detail,
		Smelly: score >= cfg.Threshold,
	}
}
