package sniff

import (
	"fmt"
	"strconv"
)

// Config groups runtime options.
type Config struct {
	DictPath     string // -dict
	Threshold    int    // -t
	MaxSize      int64  // -max
	Workers      int    // -j
	Verbose      bool   // -v
	VeryVerbose  bool   // -vv
	UltraVerbose bool   // -vvv
	CIMode       bool   // -ci
	JSON         bool   // -json
}

// ParseThreshold validates env threshold.
func ParseThreshold(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid threshold %q", s)
	}
	return n, nil
}
