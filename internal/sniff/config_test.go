// Package sniff provides functionality to detect AI-generated text.
package sniff

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseThreshold verifies that the threshold parsing
// correctly validates and converts input strings.
func TestParseThreshold(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{
			name:    "valid positive number",
			input:   "42",
			want:    42,
			wantErr: false,
		},
		{
			name:    "valid minimum threshold",
			input:   "1",
			want:    1,
			wantErr: false,
		},
		{
			name:    "zero threshold",
			input:   "0",
			want:    0,
			wantErr: true,
		},
		{
			name:    "negative threshold",
			input:   "-5",
			want:    0,
			wantErr: true,
		},
		{
			name:    "non-numeric input",
			input:   "abc",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseThreshold(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
