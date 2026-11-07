// Package state remembers what earlier runs digested: the start of the last
// successful run and the keys of every digested item.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/XiovV/digestor/internal/feed"
)

type State struct {
	// LastRun is the start of the last successful run; zero before the
	// first one.
	LastRun time.Time `json:"last_run,omitzero"`
	// Items maps the key of every digested item to its publish date, which
	// decides when the entry can be pruned.
	Items map[string]time.Time `json:"items"`
}

// Load reads the state file at path. A missing file is not an error: it
// returns an empty state, as before the first run.
func Load(path string) (*State, error) {
	s := &State{Items: map[string]time.Time{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state: %w", err)
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parsing state %s: %w", path, err)
	}
	if s.Items == nil {
		s.Items = map[string]time.Time{}
	}
	return s, nil
}

// Window returns the start of the fetch window for a run starting at now:
// the last successful run minus overlap, or now minus overlap before the
// first run, but never earlier than now minus max. capped reports that max
// cut the window short.
func (s *State) Window(now time.Time, overlap, max time.Duration) (since time.Time, capped bool) {
	since = now.Add(-overlap)
	if !s.LastRun.IsZero() {
		since = s.LastRun.Add(-overlap)
	}
	if earliest := now.Add(-max); since.Before(earliest) {
		return earliest, true
	}
	return since, false
}

// Digested reports whether any of the item's keys was digested before.
func (s *State) Digested(it feed.Item) bool {
	return slices.ContainsFunc(it.Keys, func(k string) bool {
		_, ok := s.Items[k]
		return ok
	})
}

// Add records every key of the item.
func (s *State) Add(it feed.Item) {
	for _, k := range it.Keys {
		s.Items[k] = it.Published
	}
}

// Prune drops the entries of items published before cutoff. A fetch window
// never reaches back past now minus the maximum window, so such items can't
// be fetched again.
func (s *State) Prune(cutoff time.Time) {
	for k, published := range s.Items {
		if published.Before(cutoff) {
			delete(s.Items, k)
		}
	}
}

// Save writes the state to path through a temporary file in the same
// directory, so a crash mid-write leaves the old file intact.
func (s *State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding state: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("writing state: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("writing state: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("writing state: %w", err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("writing state: %w", err)
	}
	return nil
}
