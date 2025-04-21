package sniff

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Rule describes a pattern and how to score it.
type Rule struct {
	Name        string   `json:"name"        yaml:"name"`
	Pattern     string   `json:"pattern"     yaml:"pattern"`
	Weight      int      `json:"weight"      yaml:"weight"`
	MinCount    int      `json:"minCount,omitempty"    yaml:"minCount,omitempty"`
	MinPercent  float64  `json:"minPercent,omitempty"  yaml:"minPercent,omitempty"` // 0-100
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Ext         string   `json:"ext,omitempty"         yaml:"ext,omitempty"`  // single .md
	Exts        []string `json:"exts,omitempty"        yaml:"exts,omitempty"` // [".md",".txt"]
}

// defaults
var baseRules = []Rule{
	{
		Name:    "markdown-hrule",
		Pattern: "\n---\n",
		Weight:  30,
		Ext:     ".md",
	},
	{
		Name:    "en-dash",
		Pattern: "\u2013",
		Weight:  10,
	},
	{
		Name:    "em-dash",
		Pattern: "\u2014",
		Weight:  3,
	},
	{
		Name:    "left-double-quote",
		Pattern: "\u201C",
		Weight:  10,
	},
	{
		Name:    "right-double-quote",
		Pattern: "\u201D",
		Weight:  10,
	},
	{
		Name:    "non-breaking-space",
		Pattern: "\u00A0",
		Weight:  10,
	},
}

// LoadRules merges a user dictionary with defaults.
func LoadRules(path string) ([]Rule, error) {
	if path == "" {
		return baseRules, nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ext []Rule
	switch {
	case json.Unmarshal(b, &ext) == nil:
	case yaml.Unmarshal(b, &ext) == nil:
	default:
		return nil, errors.New("dict must be JSON or YAML")
	}

	return append(baseRules, ext...), nil
}

// appliesToExt reports whether this rule should run on the file ext.
func (r Rule) appliesToExt(ext string) bool {
	if r.Ext == "" && len(r.Exts) == 0 {
		return true
	}
	if ext == r.Ext {
		return true
	}
	for _, e := range r.Exts {
		if e == ext {
			return true
		}
	}
	return false
}

// passesThresholds checks optional minCount/minPercent.
func (r Rule) passesThresholds(count int, fileLen int) bool {
	if r.MinCount > 0 && count < r.MinCount {
		return false
	}
	if r.MinPercent > 0 && fileLen > 0 {
		if 100*float64(count)/float64(fileLen) < r.MinPercent {
			return false
		}
	}
	return true
}

// RelPathExt helper
func RelPathExt(p string) string { return filepath.Ext(p) }
