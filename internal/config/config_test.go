package config

import (
	"slices"
	"strings"
	"testing"
	"time"
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

// clearEnv unsets the variables Load validates so the shell's environment
// doesn't leak into the test.
func clearEnv(t *testing.T) {
	for _, k := range []string{"GITHUB_TOKEN", "DIGESTOR_OVERLAP", "DIGESTOR_MAX_WINDOW", "CLAUDE_TIMEOUT", "SMTP_HOST", "SMTP_PORT", "GOTIFY_URL", "GOTIFY_PRIORITY"} {
		t.Setenv(k, "")
	}
}

func TestLoadGitHubToken(t *testing.T) {
	clearEnv(t)
	t.Setenv("GITHUB_TOKEN", "ghp_test")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.GitHubToken != "ghp_test" {
		t.Errorf("GitHubToken = %q, want %q", cfg.GitHubToken, "ghp_test")
	}
}

func TestLoadWindow(t *testing.T) {
	tests := []struct {
		name          string
		overlap, max  string
		wantOverlap   time.Duration
		wantMaxWindow time.Duration
		wantErr       string // substring; empty means success
	}{
		{name: "defaults", wantOverlap: 48 * time.Hour, wantMaxWindow: 168 * time.Hour},
		{name: "set", overlap: "12h", max: "72h", wantOverlap: 12 * time.Hour, wantMaxWindow: 72 * time.Hour},
		{name: "overlap equals max", overlap: "24h", max: "24h", wantOverlap: 24 * time.Hour, wantMaxWindow: 24 * time.Hour},
		{name: "overlap longer than max", overlap: "200h", wantErr: "must not be longer than DIGESTOR_MAX_WINDOW"},
		{name: "zero overlap", overlap: "0s", wantErr: "must be positive"},
		{name: "negative max", max: "-1h", wantErr: "must be positive"},
		{name: "invalid", overlap: "2d", wantErr: "DIGESTOR_OVERLAP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("DIGESTOR_OVERLAP", tt.overlap)
			t.Setenv("DIGESTOR_MAX_WINDOW", tt.max)

			cfg, err := Load()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.Overlap != tt.wantOverlap || cfg.MaxWindow != tt.wantMaxWindow {
				t.Errorf("Overlap, MaxWindow = %s, %s, want %s, %s", cfg.Overlap, cfg.MaxWindow, tt.wantOverlap, tt.wantMaxWindow)
			}
		})
	}
}
