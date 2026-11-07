package analyzer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/XiovV/digestor/internal/environment"
	"github.com/XiovV/digestor/internal/feed"
)

// fakeClaude writes a script that ignores its input and prints result inside
// the claude JSON envelope.
func fakeClaude(t *testing.T, result string) string {
	t.Helper()
	envelope, err := json.Marshal(map[string]any{"result": result})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(out, envelope, 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "claude")
	script := "#!/bin/sh\ncat >/dev/null\ncat '" + out + "'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestFilter(t *testing.T) {
	items := []feed.Item{{Title: "a"}, {Title: "b"}, {Title: "c"}}
	env := &environment.Environment{Stack: []environment.Component{{Name: "nginx"}}}

	tests := []struct {
		name   string
		result string
		want   []Finding // compared by title, relevance and summary
	}{
		{
			name:   "every item rated",
			result: `[{"index": 0, "relevance": "high", "summary": "s"}, {"index": 1, "relevance": "none", "summary": "Windows-only"}, {"index": 2, "relevance": "none", "summary": "duplicate of [0]"}]`,
			want: []Finding{
				{Item: items[0], Relevance: "high", Summary: "s"},
				{Item: items[1], Relevance: NotRelevant, Summary: "Windows-only"},
				{Item: items[2], Relevance: NotRelevant, Summary: "duplicate of [0]"},
			},
		},
		{
			name:   "missing items become not relevant",
			result: `[{"index": 1, "relevance": "low", "summary": "s"}]`,
			want: []Finding{
				{Item: items[1], Relevance: "low", Summary: "s"},
				{Item: items[0], Relevance: NotRelevant},
				{Item: items[2], Relevance: NotRelevant},
			},
		},
		{
			name:   "unknown and repeated indexes are dropped",
			result: `[{"index": 7, "relevance": "high"}, {"index": 0, "relevance": "low", "summary": "first"}, {"index": 0, "relevance": "high", "summary": "second"}]`,
			want: []Finding{
				{Item: items[0], Relevance: "low", Summary: "first"},
				{Item: items[1], Relevance: NotRelevant},
				{Item: items[2], Relevance: NotRelevant},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClaudeCLI{Bin: fakeClaude(t, tt.result), Timeout: 10 * time.Second}
			got, err := c.Filter(context.Background(), items, env)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d findings, want %d: %+v", len(got), len(tt.want), got)
			}
			for i, w := range tt.want {
				g := got[i]
				if g.Item.Title != w.Item.Title || g.Relevance != w.Relevance || g.Summary != w.Summary {
					t.Errorf("finding %d = {%s %s %q}, want {%s %s %q}", i,
						g.Item.Title, g.Relevance, g.Summary, w.Item.Title, w.Relevance, w.Summary)
				}
			}
		})
	}
}
