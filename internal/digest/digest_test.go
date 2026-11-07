package digest

import (
	"strings"
	"testing"
	"time"

	"github.com/XiovV/digestor/internal/analyzer"
	"github.com/XiovV/digestor/internal/feed"
)

func TestMarkdownSkipped(t *testing.T) {
	skipped := []analyzer.Finding{
		{Item: feed.Item{Title: "Windows bug", Link: "https://news.example/1"}, Relevance: analyzer.NotRelevant, Summary: "Windows-only"},
		{Item: feed.Item{Title: "Unrated"}, Relevance: analyzer.NotRelevant},
	}
	finding := analyzer.Finding{Item: feed.Item{Title: "nginx CVE"}, Relevance: "high", Summary: "patch it"}

	tests := []struct {
		name     string
		findings []analyzer.Finding
		skipped  []analyzer.Finding
		want     []string
		absent   []string
	}{
		{
			name:    "only skipped",
			skipped: skipped,
			want: []string{
				"0 relevant of 2",
				"Nothing relevant to your environment.",
				"## Not relevant (2)\n- Windows bug: Windows-only\n  <https://news.example/1>\n- Unrated: no reason given\n",
			},
		},
		{
			name:     "findings and skipped",
			findings: []analyzer.Finding{finding},
			skipped:  skipped[:1],
			want:     []string{"1 relevant of 2", "## [HIGH] nginx CVE", "## Not relevant (1)"},
			absent:   []string{"Nothing relevant"},
		},
		{
			name:     "nothing skipped",
			findings: []analyzer.Finding{finding},
			absent:   []string{"Not relevant"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Digest{
				GeneratedAt: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC),
				ItemsSeen:   len(tt.findings) + len(tt.skipped),
				Findings:    tt.findings,
				Skipped:     tt.skipped,
			}
			got := d.Markdown()
			for _, s := range tt.want {
				if !strings.Contains(got, s) {
					t.Errorf("markdown missing %q:\n%s", s, got)
				}
			}
			for _, s := range tt.absent {
				if strings.Contains(got, s) {
					t.Errorf("markdown unexpectedly contains %q:\n%s", s, got)
				}
			}
		})
	}
}
