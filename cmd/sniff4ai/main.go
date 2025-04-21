// Package main is the CLI entry‑point for synthsniff.
package main

import (
	"flag"
	"log"
	"os"
	"runtime"

	"github.com/JoobyPM/synthsniff/internal/sniff"
)

const (
	envThreshold     = "SYNTHSNIFF_THRESHOLD"
	defaultThreshold = 30
	exitSmelly       = 1
)

func main() {
	// Set GOMAXPROCS to the number of available cores, but not more than 4
	maxProcs := runtime.NumCPU()
	if maxProcs > 4 {
		maxProcs = 4
	}
	runtime.GOMAXPROCS(maxProcs)

	cfg, paths := parseFlags()
	if len(paths) == 0 {
		log.Fatal("at least one file or directory is required")
	}

	results, err := sniff.Scan(paths, cfg)
	if err != nil {
		log.Fatal(err)
	}

	if sniff.Render(results, cfg) && cfg.CIMode {
		os.Exit(exitSmelly)
	}
}

func parseFlags() (sniff.Config, []string) {
	var cfg sniff.Config
	flag.StringVar(&cfg.DictPath, "dict", "", "JSON/YAML with extra rules")
	flag.IntVar(&cfg.Threshold, "t", -1, "score threshold (env SYNTHSNIFF_THRESHOLD)")
	flag.Int64Var(&cfg.MaxSize, "max", 10<<20, "max file size (bytes)")
	flag.IntVar(&cfg.Workers, "j", 0, "parallel workers (default = CPUs)")

	flag.BoolVar(&cfg.Verbose, "v", false, "verbose per‑file counts")
	flag.BoolVar(&cfg.VeryVerbose, "vv", false, "very verbose with rule names")
	flag.BoolVar(&cfg.UltraVerbose, "vvv", false, "ultra verbose with rule metadata")

	flag.BoolVar(&cfg.CIMode, "ci", false, "exit non‑zero on AI smell")
	flag.BoolVar(&cfg.JSON, "json", false, "machine‑readable JSON output")
	flag.BoolVar(&cfg.UseGitignore, "use-gitignore", false, "respect .gitignore files")
	flag.StringVar(&cfg.IgnoreFile, "ignore-file", "", "custom ignore file path")
	flag.Parse()

	if cfg.Threshold == -1 {
		if v := os.Getenv(envThreshold); v != "" {
			if th, err := sniff.ParseThreshold(v); err == nil {
				cfg.Threshold = th
			}
		}
	}
	if cfg.Threshold < 0 {
		cfg.Threshold = defaultThreshold
	}

	return cfg, flag.Args()
}
