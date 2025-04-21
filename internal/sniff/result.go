package sniff

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Render prints results to stdout.
//
// If cfg.JSON is true, it prints JSON to stdout.
// Otherwise, it prints text to stdout.
func Render(list []Result, cfg Config) bool {
	if cfg.JSON {
		return renderJSON(list)
	}

	for _, r := range list {
		switch {
		case cfg.UltraVerbose:
			printUltra(r)
		case cfg.VeryVerbose:
			printVery(r)
		case cfg.Verbose && r.Smelly:
			printSmelly(r, true)
		case r.Smelly:
			printSmelly(r, false)
		}
	}

	if cfg.UltraVerbose || cfg.VeryVerbose {
		return anySmelly(list)
	}
	if !anySmelly(list) {
		fmt.Printf("✅ No AI smell detected in %d file(s)\n", len(list))
	}

	// Print loaded ignore files report
	printIgnoreFilesReport(cfg)

	return anySmelly(list)
}

/* ---------- JSON ---------- */

func renderJSON(list []Result) bool {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(list); err != nil {
		fmt.Fprintf(os.Stderr, "json encode error: %v\n", err)
	}
	return anySmelly(list)
}

/* ---------- text helpers ---------- */

func anySmelly(rs []Result) bool {
	for _, r := range rs {
		if r.Smelly {
			return true
		}
	}
	return false
}

func printSmelly(r Result, verbose bool) {
	const siren = "🚨 "
	if verbose {
		fmt.Printf("%s%s (score %d) %v\n", siren, r.Path, r.Score, hitCounts(r))
		return
	}
	fmt.Printf("%s%s\t(score %d)\n", siren, r.Path, r.Score)
}

func printVery(r Result) {
	icon := "✅"
	if r.Smelly {
		icon = "🚨"
	}
	fmt.Printf("%s %s (score %d)\n", icon, r.Path, r.Score)
	for name, h := range r.Detail {
		fmt.Printf("  %s × %d\n", name, h.Count)
	}
}

func printUltra(r Result) {
	icon := "✅"
	if r.Smelly {
		icon = "🚨"
	}
	fmt.Printf("%s %s (score %d)\n", icon, r.Path, r.Score)
	keys := make([]string, 0, len(r.Detail))
	for k := range r.Detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, n := range keys {
		h := r.Detail[n]
		fmt.Printf("  %s × %d (pattern=%q weight=%d)\n",
			h.Rule.Name, h.Count, escape(h.Rule.Pattern), h.Rule.Weight)
	}
}

func hitCounts(r Result) map[string]int {
	out := make(map[string]int, len(r.Detail))
	for n, h := range r.Detail {
		out[n] = h.Count
	}
	return out
}

func escape(s string) string {
	return strings.NewReplacer("\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(s)
}

// printIgnoreFilesReport prints information about loaded gitignore files
func printIgnoreFilesReport(cfg Config) {
	// Always print when gitignore is enabled and files are loaded
	if !cfg.UseGitignore || len(LoadedIgnoreFiles) == 0 {
		return
	}

	fmt.Println("\nLoaded ignore files:")
	for _, path := range LoadedIgnoreFiles {
		fmt.Printf("  - %s\n", path)
	}
}
