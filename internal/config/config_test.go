package config

import (
	"slices"
	"testing"
)

func TestParseList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "https://a.example/feed", []string{"https://a.example/feed"}},
		{"comma", "https://a.example, https://b.example", []string{"https://a.example", "https://b.example"}},
		{"newline", "https://a.example\nhttps://b.example\r\n", []string{"https://a.example", "https://b.example"}},
		{"blanks", " , ,\n https://a.example ,", []string{"https://a.example"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseList(tt.in); !slices.Equal(got, tt.want) {
				t.Errorf("ParseList(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
