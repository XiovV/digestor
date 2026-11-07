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

// clearEnv unsets the variables Load validates so the shell's environment
// doesn't leak into the test.
func clearEnv(t *testing.T) {
	for _, k := range []string{"RSS_FEEDS", "GITHUB_TOKEN", "DIGESTOR_LOOKBACK", "CLAUDE_TIMEOUT", "SMTP_HOST", "SMTP_PORT", "GOTIFY_URL", "GOTIFY_PRIORITY"} {
		t.Setenv(k, "")
	}
}

func TestLoadFeedsOptional(t *testing.T) {
	clearEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Feeds) != 0 {
		t.Errorf("Feeds = %q, want none", cfg.Feeds)
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
