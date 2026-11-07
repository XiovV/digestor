package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/XiovV/digestor/internal/advisory"
	"github.com/XiovV/digestor/internal/analyzer"
	"github.com/XiovV/digestor/internal/config"
	"github.com/XiovV/digestor/internal/digest"
	"github.com/XiovV/digestor/internal/environment"
	"github.com/XiovV/digestor/internal/feed"
	"github.com/XiovV/digestor/internal/notify"
)

// passAnalyzer stands in for Claude: every item becomes a low finding, so
// nothing is researched.
type passAnalyzer struct{}

func (passAnalyzer) Filter(_ context.Context, items []feed.Item, _ *environment.Environment) ([]analyzer.Finding, error) {
	var out []analyzer.Finding
	for _, it := range items {
		out = append(out, analyzer.Finding{Item: it, Relevance: "low"})
	}
	return out, nil
}

func (passAnalyzer) Research(_ context.Context, f analyzer.Finding, _ *environment.Environment) (analyzer.Finding, error) {
	return f, errors.New("research not expected")
}

type recorder struct{ sent []digest.Digest }

func (r *recorder) Name() string { return "recorder" }

func (r *recorder) Send(_ context.Context, d digest.Digest) error {
	r.sent = append(r.sent, d)
	return nil
}

func TestRunSources(t *testing.T) {
	newsPublished := time.Now().Add(-time.Hour)
	advisoryPublished := time.Now().Add(-2 * time.Hour)

	tests := []struct {
		name       string
		feeds      string   // none, ok or fail
		advisories string   // none, ok or fail
		wantGUIDs  []string // nil means no digest is sent
		wantErr    string   // substring; empty means success
	}{
		{name: "advisories only", feeds: "none", advisories: "ok", wantGUIDs: []string{"GHSA-aaaa-bbbb-cccc"}},
		{name: "feeds only", feeds: "ok", advisories: "none", wantGUIDs: []string{"news-1"}},
		{name: "feeds and advisories", feeds: "ok", advisories: "ok", wantGUIDs: []string{"news-1", "GHSA-aaaa-bbbb-cccc"}},
		{name: "feeds fail", feeds: "fail", advisories: "ok", wantGUIDs: []string{"GHSA-aaaa-bbbb-cccc"}, wantErr: "fetching feeds"},
		{name: "advisories fail", feeds: "ok", advisories: "fail", wantGUIDs: []string{"news-1"}, wantErr: "fetching advisories"},
		{name: "everything fails", feeds: "fail", advisories: "fail", wantErr: "fetching advisories"},
		{name: "no sources", feeds: "none", advisories: "none", wantErr: "no sources"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /feed", func(w http.ResponseWriter, r *http.Request) {
				if tt.feeds == "fail" {
					http.Error(w, "boom", http.StatusInternalServerError)
					return
				}
				fmt.Fprintf(w, `<?xml version="1.0"?><rss version="2.0"><channel><title>News</title>
<item><title>Caddy news</title><link>https://news.example/1</link><guid>news-1</guid><pubDate>%s</pubDate></item>
</channel></rss>`, newsPublished.Format(time.RFC1123Z))
			})
			mux.HandleFunc("GET /advisories", func(w http.ResponseWriter, r *http.Request) {
				if tt.advisories == "fail" {
					http.Error(w, "boom", http.StatusInternalServerError)
					return
				}
				fmt.Fprintf(w, `[{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "summary": "Caddy advisory",
"html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "published_at": %q}]`,
					advisoryPublished.UTC().Format(time.RFC3339))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			cfg := &config.Config{Lookback: 24 * time.Hour}
			if tt.feeds != "none" {
				cfg.Feeds = []string{srv.URL + "/feed"}
			}
			env := &environment.Environment{
				Stack:             []environment.Component{{Name: "Caddy"}},
				ResearchRelevance: []string{"critical", "high"},
			}
			if tt.advisories != "none" {
				env.Advisories.GitHub = []environment.GitHubQuery{{Affects: []string{"github.com/caddyserver/caddy/v2"}}}
			}
			rec := &recorder{}
			a := &App{
				Config:     cfg,
				Env:        env,
				Analyzer:   passAnalyzer{},
				Advisories: &advisory.Client{GitHubURL: srv.URL},
				Notifiers:  []notify.Notifier{rec},
			}

			err := a.Run(context.Background())
			if tt.wantErr == "" && err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("Run() error = %v, want it to contain %q", err, tt.wantErr)
			}

			if tt.wantGUIDs == nil {
				if len(rec.sent) != 0 {
					t.Errorf("sent %d digests, want none", len(rec.sent))
				}
				return
			}
			if len(rec.sent) != 1 {
				t.Fatalf("sent %d digests, want 1", len(rec.sent))
			}
			d := rec.sent[0]
			var got []string
			for _, f := range d.Findings {
				got = append(got, f.Item.GUID)
			}
			if !slices.Equal(got, tt.wantGUIDs) || d.ItemsSeen != len(tt.wantGUIDs) {
				t.Errorf("digest has %q of %d items, want %q", got, d.ItemsSeen, tt.wantGUIDs)
			}
		})
	}
}
