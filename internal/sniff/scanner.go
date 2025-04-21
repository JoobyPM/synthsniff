package sniff

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// getMaxProcs returns the number of available cores, limited to 4
func getMaxProcs() int {
	maxProcs := runtime.NumCPU()
	if maxProcs > 4 {
		maxProcs = 4
	}
	return maxProcs
}

// mmapGate limits concurrent mmap/munmap operations
var mmapGate = make(chan struct{}, getMaxProcs())

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
	// Load rules
	rules, err := LoadRules(cfg.DictPath)
	if err != nil {
		return nil, err
	}

	// Set number of workers
	numWorkers := cfg.Workers
	if numWorkers <= 0 {
		numWorkers = getMaxProcs()
	}

	// Create job channels for each worker (buffered with size 4)
	jobChannels := make([]chan []string, numWorkers)
	for i := 0; i < numWorkers; i++ {
		jobChannels[i] = make(chan []string, 4)
	}

	// Create a shared results channel
	resultsChan := make(chan Result, numWorkers)

	// Start worker goroutines
	var workersWg sync.WaitGroup
	workersWg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer workersWg.Done()
			// Each worker processes files from its own dedicated channel
			for paths := range jobChannels[workerID] {
				for _, path := range paths {
					resultsChan <- analyse(path, rules, cfg)
				}
			}
		}(i)
	}

	// Start a goroutine to close the results channel when all workers are done
	go func() {
		workersWg.Wait()
		close(resultsChan)
	}()

	// Start a goroutine to walk the directories and distribute files to workers
	walkerErrorChan := make(chan error, 1)
	go func() {
		defer func() {
			// Close all job channels when traversal is complete
			for _, ch := range jobChannels {
				close(ch)
			}
		}()

		err := walkDirBreadthFirst(roots, cfg.DictPath, jobChannels)
		walkerErrorChan <- err
	}()

	// Collect results as they arrive
	var results []Result
	for result := range resultsChan {
		results = append(results, result)
	}

	// Check if the directory walker encountered an error
	if err := <-walkerErrorChan; err != nil {
		return nil, err
	}

	// Sort results by path
	sort.Slice(results, func(i, j int) bool {
		return results[i].Path < results[j].Path
	})

	return results, nil
}

// walkDirBreadthFirst walks directories breadth-first and sends files to job channels
func walkDirBreadthFirst(roots []string, dictPath string, jobChannels []chan []string) error {
	// Constants
	const batchSize = 32 // Size of each batch of paths

	// Keep track of the next worker to send files to
	nextWorker := 0
	numWorkers := len(jobChannels)

	// Create a queue for breadth-first traversal
	dirQueue := []string{}

	// Keep track of the current batch for each worker
	currentBatches := make([][]string, numWorkers)

	// Helper function to send a batch if it's full
	sendBatchIfFull := func(workerID int) {
		if len(currentBatches[workerID]) >= batchSize {
			jobChannels[workerID] <- currentBatches[workerID]
			currentBatches[workerID] = make([]string, 0, batchSize)
		}
	}

	// Add initial roots to the queue
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			return err
		}

		if info.IsDir() {
			dirQueue = append(dirQueue, root)
		} else {
			// Skip dictionary file
			if dictPath != "" && filepath.Clean(root) == filepath.Clean(dictPath) {
				continue
			}

			// Add file to the next worker's batch
			currentBatches[nextWorker] = append(currentBatches[nextWorker], root)
			sendBatchIfFull(nextWorker)

			// Round-robin to the next worker
			nextWorker = (nextWorker + 1) % numWorkers
		}
	}

	// Process directories breadth-first
	for len(dirQueue) > 0 {
		// Get the next directory from the queue
		dir := dirQueue[0]
		dirQueue = dirQueue[1:]

		// Read directory entries
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}

		// Process each entry
		for _, entry := range entries {
			entryPath := filepath.Join(dir, entry.Name())

			if entry.IsDir() {
				// Skip .git directories
				if entry.Name() == ".git" {
					continue
				}

				// Add subdirectory to the queue for breadth-first traversal
				dirQueue = append(dirQueue, entryPath)
			} else {
				// Skip dictionary file
				if dictPath != "" && filepath.Clean(entryPath) == filepath.Clean(dictPath) {
					continue
				}

				// Skip rule files by checking extension
				ext := strings.ToLower(filepath.Ext(entryPath))
				if ext == ".yaml" || ext == ".yml" || ext == ".json" {
					// For potential rule files, check content
					data, err := os.ReadFile(entryPath)
					if err == nil && len(data) > 0 {
						content := string(data)
						if strings.Contains(content, "pattern") && strings.Contains(content, "weight") {
							// Looks like a rules file, skip it
							continue
						}
					}
				}

				// Add file to the next worker's batch using round-robin
				currentBatches[nextWorker] = append(currentBatches[nextWorker], entryPath)
				sendBatchIfFull(nextWorker)

				// Move to the next worker
				nextWorker = (nextWorker + 1) % numWorkers
			}
		}
	}

	// Send any remaining partial batches
	for i, batch := range currentBatches {
		if len(batch) > 0 {
			jobChannels[i] <- batch
		}
	}

	return nil
}

func analyse(path string, rules []Rule, cfg Config) Result {
	// Use memory mapping to read file content instead of ReadFile
	// This reduces syscall overhead by avoiding extra copies
	mmapGate <- struct{}{} // acquire
	data, isMapped, err := mmapFile(path)
	<-mmapGate // release ASAP
	if err != nil {
		return Result{Path: path}
	}

	// Only unmap memory-mapped files
	if isMapped {
		defer func() {
			mmapGate <- struct{}{} // acquire
			if err := unmapFile(data); err != nil {
				log.Printf("failed to unmap file: %v", err)
			}
			<-mmapGate // release ASAP
		}()
	}

	// Skip binary files
	if bytes.IndexByte(data, 0) != -1 {
		return Result{Path: path}
	}

	// Check size limit after reading
	if cfg.MaxSize > 0 && int64(len(data)) > cfg.MaxSize {
		return Result{Path: path}
	}

	fileExt := filepath.Ext(path)
	score := 0
	detail := make(map[string]RuleHit)

	// Convert to string once to avoid repeated conversions for each rule
	content := string(data)
	fileLen := len(data)

	// Check each rule against the file content
	for _, r := range rules {
		// Skip rules that don't apply to this file extension
		if !r.appliesToExt(fileExt) {
			continue
		}

		// Count pattern occurrences using strings.Count (more efficient than bytes.Count)
		count := strings.Count(content, r.Pattern)

		// Skip patterns that don't match or don't pass thresholds
		if count == 0 || !r.passesThresholds(count, fileLen) {
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
