package analyzer

import (
	"strings"
	"testing"
	"time"

	"github.com/XiovV/digestor/internal/environment"
	"github.com/XiovV/digestor/internal/feed"
)

func TestFilterPrompt(t *testing.T) {
	items := []feed.Item{{Title: "nginx CVE", Published: time.Now()}}
	stack := []environment.Component{{Name: "nginx"}}

	tests := []struct {
		name   string
		prompt string
		want   string
		absent string
	}{
		{name: "default", prompt: "", want: defaultPrompt},
		{name: "custom", prompt: "Only report critical issues.", want: "Only report critical issues.", absent: defaultPrompt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filterPrompt(items, &environment.Environment{Prompt: tt.prompt, Stack: stack})
			if err != nil {
				t.Fatal(err)
			}

			for _, s := range []string{tt.want, "Respond with ONLY a JSON array", "name: nginx", "[0] nginx CVE"} {
				if !strings.Contains(got, s) {
					t.Errorf("prompt missing %q", s)
				}
			}
			if tt.absent != "" && strings.Contains(got, tt.absent) {
				t.Errorf("prompt unexpectedly contains %q", tt.absent)
			}
		})
	}
}

func TestResearchPrompt(t *testing.T) {
	f := Finding{Item: feed.Item{Title: "nginx CVE"}, Affected: []string{"nginx"}}
	stack := []environment.Component{{Name: "nginx"}}

	tests := []struct {
		name   string
		prompt string
		want   string
		absent string
	}{
		{name: "default", prompt: "", want: defaultResearchPrompt},
		{name: "custom", prompt: "Keep it under 500 characters.", want: "Keep it under 500 characters.", absent: defaultResearchPrompt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := researchPrompt(f, &environment.Environment{ResearchPrompt: tt.prompt, Stack: stack})
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range []string{tt.want, "Respond with ONLY a JSON object", "name: nginx", "Title: nginx CVE"} {
				if !strings.Contains(got, s) {
					t.Errorf("prompt missing %q", s)
				}
			}
			if tt.absent != "" && strings.Contains(got, tt.absent) {
				t.Errorf("prompt unexpectedly contains %q", tt.absent)
			}
		})
	}
}
