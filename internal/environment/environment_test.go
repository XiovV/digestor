package environment

import (
	"os"
	"path/filepath"
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
	env := &Environment{Prompt: "SECRET INSTRUCTIONS", ResearchPrompt: "RESEARCH INSTRUCTIONS", Context: "Homelab.", Stack: []Component{{Name: "nginx"}}}

	desc, err := env.Describe()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(desc, "SECRET INSTRUCTIONS") || strings.Contains(desc, "RESEARCH INSTRUCTIONS") || !strings.Contains(desc, "nginx") || !strings.Contains(desc, "Homelab.") {
		t.Errorf("Describe() = %q", desc)
	}
}
