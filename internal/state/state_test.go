package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/XiovV/digestor/internal/feed"
)

var now = time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)

func TestWindow(t *testing.T) {
	tests := []struct {
		name       string
		lastRun    time.Time
		wantSince  time.Time
		wantCapped bool
	}{
		{name: "first run", wantSince: now.Add(-48 * time.Hour)},
		{name: "recent run", lastRun: now.Add(-time.Hour), wantSince: now.Add(-49 * time.Hour)},
		{name: "at the cap", lastRun: now.Add(-120 * time.Hour), wantSince: now.Add(-168 * time.Hour)},
		{name: "past the cap", lastRun: now.Add(-30 * 24 * time.Hour), wantSince: now.Add(-168 * time.Hour), wantCapped: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{LastRun: tt.lastRun}
			since, capped := s.Window(now, 48*time.Hour, 168*time.Hour)
			if !since.Equal(tt.wantSince) || capped != tt.wantCapped {
				t.Errorf("Window() = %v, %t, want %v, %t", since, capped, tt.wantSince, tt.wantCapped)
			}
		})
	}
}

func TestDigested(t *testing.T) {
	s := &State{Items: map[string]time.Time{}}
	s.Add(feed.Item{Keys: []string{"GHSA-aaaa-bbbb-cccc", "CVE-2026-1"}, Published: now})

	tests := []struct {
		name string
		keys []string
		want bool
	}{
		{name: "same primary id", keys: []string{"GHSA-aaaa-bbbb-cccc"}, want: true},
		{name: "shared alias", keys: []string{"GO-2026-1", "CVE-2026-1"}, want: true},
		{name: "unrelated", keys: []string{"GHSA-dddd-eeee-ffff"}},
		{name: "no keys"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.Digested(feed.Item{Keys: tt.keys}); got != tt.want {
				t.Errorf("Digested(%q) = %t, want %t", tt.keys, got, tt.want)
			}
		})
	}
}

func TestPrune(t *testing.T) {
	s := &State{Items: map[string]time.Time{
		"old":    now.Add(-8 * 24 * time.Hour),
		"cutoff": now.Add(-7 * 24 * time.Hour),
		"new":    now.Add(-time.Hour),
	}}
	s.Prune(now.Add(-7 * 24 * time.Hour))

	if _, ok := s.Items["old"]; ok {
		t.Error("old entry was kept")
	}
	for _, k := range []string{"cutoff", "new"} {
		if _, ok := s.Items[k]; !ok {
			t.Errorf("%s entry was pruned", k)
		}
	}
}

func TestLoadMissing(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !s.LastRun.IsZero() || len(s.Items) != 0 {
		t.Errorf("Load() = %+v, want an empty state", s)
	}
	// Items must be usable, not a nil map.
	s.Add(feed.Item{Keys: []string{"k"}, Published: now})
}

func TestLoadInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load() error = nil, want a parse error")
	}
}

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := &State{LastRun: now, Items: map[string]time.Time{}}
	s.Add(feed.Item{Keys: []string{"https://news.example/feed news-1"}, Published: now.Add(-time.Hour)})
	if err := s.Save(path); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !got.LastRun.Equal(now) {
		t.Errorf("LastRun = %v, want %v", got.LastRun, now)
	}
	if p, ok := got.Items["https://news.example/feed news-1"]; !ok || !p.Equal(now.Add(-time.Hour)) {
		t.Errorf("Items = %v, want the saved entry", got.Items)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("directory has %d files after Save, want only the state file", len(entries))
	}
}
