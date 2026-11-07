package environment

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string // substring; empty means success
	}{
		{
			name: "valid",
			yaml: `
prompt: Be brief.
research_prompt: Cite CVEs.
context: Homelab.
stack:
  - name: nginx
    vendor: F5
    type: service
    version: "1.24"
    exposure: internet
    notes: Reverse proxy
  - name: Debian
`,
		},
		{name: "empty file", yaml: "", wantErr: "at least one component"},
		{name: "empty stack", yaml: "stack: []", wantErr: "at least one component"},
		{name: "missing name", yaml: "stack:\n  - version: \"1\"", wantErr: "stack[0]: name is required"},
		{name: "bad exposure", yaml: "stack:\n  - name: nginx\n    exposure: public", wantErr: `exposure "public"`},
		{name: "unknown key", yaml: "stack:\n  - name: nginx\n    exposre: internet", wantErr: "exposre"},
		{name: "bad research relevance", yaml: "research_relevance: [urgent]\nstack:\n  - name: nginx", wantErr: `research_relevance: "urgent"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "environment.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}

			env, err := Load(path)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if len(env.Stack) != 2 || env.Stack[0].Exposure != "internet" {
					t.Errorf("Load() = %+v", env)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadResearchRelevance(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{name: "default", yaml: "", want: []string{"critical", "high"}},
		{name: "custom", yaml: "research_relevance: [critical, high, medium]\n", want: []string{"critical", "high", "medium"}},
		{name: "disabled", yaml: "research_relevance: []\n", want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "environment.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml+"stack:\n  - name: nginx\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			env, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if !slices.Equal(env.ResearchRelevance, tt.want) {
				t.Errorf("ResearchRelevance = %v, want %v", env.ResearchRelevance, tt.want)
			}
		})
	}
}

func TestDescribeOmitsPrompts(t *testing.T) {
	env := &Environment{Prompt: "SECRET INSTRUCTIONS", ResearchPrompt: "RESEARCH INSTRUCTIONS", Context: "Homelab.", Stack: []Component{{Name: "nginx"}},
		Feeds: []string{"https://news.example/feed"}}

	desc, err := env.Describe()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(desc, "SECRET INSTRUCTIONS") || strings.Contains(desc, "RESEARCH INSTRUCTIONS") || strings.Contains(desc, "news.example") ||
		!strings.Contains(desc, "nginx") || !strings.Contains(desc, "Homelab.") {
		t.Errorf("Describe() = %q", desc)
	}
}

func TestLoadFeeds(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    []string
		wantErr string // substring; empty means success
	}{
		{
			name: "valid",
			yaml: "feeds:\n  - https://feeds.feedburner.com/TheHackersNews\n  - http://news.example/rss?x=1\n",
			want: []string{"https://feeds.feedburner.com/TheHackersNews", "http://news.example/rss?x=1"},
		},
		{name: "none", yaml: ""},
		{name: "not a URL", yaml: "feeds: [news]\n", wantErr: `feeds[0]: "news" must be an http(s) URL`},
		{name: "other scheme", yaml: "feeds: [\"ftp://news.example/feed\"]\n", wantErr: `feeds[0]: "ftp://news.example/feed" must be an http(s) URL`},
		{name: "no host", yaml: "feeds: [\"https:///feed\"]\n", wantErr: `feeds[0]: "https:///feed" must be an http(s) URL`},
		{name: "relative", yaml: "feeds: [/feed]\n", wantErr: `feeds[0]: "/feed" must be an http(s) URL`},
		{
			name:    "duplicate",
			yaml:    "feeds:\n  - https://news.example/a\n  - https://news.example/b\n  - https://news.example/a\n",
			wantErr: "feeds[2]: duplicate of feeds[0]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "environment.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml+"stack:\n  - name: nginx\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			env, err := Load(path)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if !slices.Equal(env.Feeds, tt.want) {
					t.Errorf("Feeds = %q, want %q", env.Feeds, tt.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadAdvisories(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    Advisories
		wantErr string // substring; empty means success
	}{
		{
			name: "minimal",
			yaml: `
advisories:
  github:
    - affects: [github.com/caddyserver/caddy/v2]
  github_repos:
    - caddyserver/caddy
  osv:
    - purl: pkg:golang/stdlib
`,
			want: Advisories{
				GitHub:      []GitHubQuery{{Affects: []string{"github.com/caddyserver/caddy/v2"}}},
				GitHubRepos: []string{"caddyserver/caddy"},
				OSV:         []OSVQuery{{PURL: "pkg:golang/stdlib"}},
			},
		},
		{
			name: "all fields",
			yaml: `
advisories:
  github:
    - name: Caddy
      ecosystem: go
      affects: [github.com/caddyserver/caddy/v2@2.11.2, golang.org/x/net]
      severity: high
      type: reviewed
      cwes: [CWE-79]
  osv:
    - name: Go
      ecosystem: Go
      package: stdlib
      version: "1.23.0"
`,
			want: Advisories{
				GitHub: []GitHubQuery{{
					Name:      "Caddy",
					Ecosystem: "go",
					Affects:   []string{"github.com/caddyserver/caddy/v2@2.11.2", "golang.org/x/net"},
					Severity:  "high",
					Type:      "reviewed",
					CWEs:      []string{"CWE-79"},
				}},
				OSV: []OSVQuery{{Name: "Go", Ecosystem: "Go", Package: "stdlib", Version: "1.23.0"}},
			},
		},
		{name: "none", yaml: ""},
		{
			name:    "github without filter",
			yaml:    "advisories:\n  github:\n    - name: Caddy\n      severity: high\n",
			wantErr: "advisories.github[0] (Caddy): set at least one of ecosystem, affects or cwes",
		},
		{name: "github bad ecosystem", yaml: "advisories:\n  github:\n    - ecosystem: golang\n", wantErr: `advisories.github[0]: ecosystem "golang"`},
		{name: "github bad severity", yaml: "advisories:\n  github:\n    - ecosystem: go\n      severity: moderate\n", wantErr: `advisories.github[0]: severity "moderate"`},
		{name: "github bad type", yaml: "advisories:\n  github:\n    - ecosystem: go\n      type: all\n", wantErr: `advisories.github[0]: type "all"`},
		{name: "repo without owner", yaml: "advisories:\n  github_repos: [caddy]\n", wantErr: `advisories.github_repos[0]: "caddy" must be owner/name`},
		{name: "repo with extra path", yaml: "advisories:\n  github_repos: [caddyserver/caddy/issues]\n", wantErr: `advisories.github_repos[0]: "caddyserver/caddy/issues" must be owner/name`},
		{name: "repo with empty owner", yaml: "advisories:\n  github_repos: [/caddy]\n", wantErr: `advisories.github_repos[0]: "/caddy" must be owner/name`},
		{name: "osv empty", yaml: "advisories:\n  osv:\n    - name: Go\n", wantErr: "advisories.osv[0] (Go): set either purl or ecosystem+package"},
		{name: "osv package without ecosystem", yaml: "advisories:\n  osv:\n    - package: stdlib\n", wantErr: "advisories.osv[0]: set either purl or ecosystem+package"},
		{name: "osv purl and package", yaml: "advisories:\n  osv:\n    - purl: pkg:golang/stdlib\n      ecosystem: Go\n      package: stdlib\n", wantErr: "advisories.osv[0]: set either purl or ecosystem+package"},
		{name: "osv version with purl", yaml: "advisories:\n  osv:\n    - purl: pkg:golang/stdlib\n      version: \"1.23.0\"\n", wantErr: "advisories.osv[0]: version needs ecosystem+package"},
		{name: "unknown key", yaml: "advisories:\n  github:\n    - affect: [x]\n", wantErr: "affect"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "environment.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml+"stack:\n  - name: nginx\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			env, err := Load(path)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if !reflect.DeepEqual(env.Advisories, tt.want) {
					t.Errorf("Advisories = %+v, want %+v", env.Advisories, tt.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestAdvisoriesLen(t *testing.T) {
	a := Advisories{
		GitHub:      []GitHubQuery{{Ecosystem: "go"}, {Ecosystem: "npm"}},
		GitHubRepos: []string{"caddyserver/caddy"},
		OSV:         []OSVQuery{{PURL: "pkg:golang/stdlib"}},
	}
	if got := a.Len(); got != 4 {
		t.Errorf("Len() = %d, want 4", got)
	}
	if got := (Advisories{}).Len(); got != 0 {
		t.Errorf("empty Len() = %d, want 0", got)
	}
}
