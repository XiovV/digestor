// Package app wires the pipeline: fetch → filter → research → notify.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"time"

	"github.com/XiovV/digestor/internal/advisory"
	"github.com/XiovV/digestor/internal/analyzer"
	"github.com/XiovV/digestor/internal/config"
	"github.com/XiovV/digestor/internal/digest"
	"github.com/XiovV/digestor/internal/environment"
	"github.com/XiovV/digestor/internal/feed"
	"github.com/XiovV/digestor/internal/notify"
	"github.com/XiovV/digestor/internal/state"
)

type App struct {
	Config     *config.Config
	Env        *environment.Environment
	Analyzer   analyzer.Analyzer
	Advisories *advisory.Client
	Notifiers  []notify.Notifier
	// DryRun reads the state but never writes it.
	DryRun bool
}

func (a *App) Run(ctx context.Context) error {
	start := time.Now()
	st, err := state.Load(a.Config.StateFile)
	if err != nil {
		return err
	}
	if st.LastRun.IsZero() {
		slog.Info("no successful run recorded yet, treating this as the first run", "state", a.Config.StateFile)
	}
	since, capped := st.Window(start, a.Config.Overlap, a.Config.MaxWindow)
	if capped {
		slog.Warn("last successful run is older than the maximum window; items before the window are not fetched",
			"last_run", st.LastRun.Format(time.RFC3339), "max_window", a.Config.MaxWindow)
	}

	names := make([]string, len(a.Notifiers))
	for i, n := range a.Notifiers {
		names[i] = n.Name()
	}
	slog.Info("starting run", "feeds", len(a.Env.Feeds), "advisory_queries", a.Env.Advisories.Len(),
		"since", since.Format(time.RFC3339), "notifiers", names)

	fetched, errs, err := a.fetch(ctx, since)
	if err != nil {
		return err
	}
	var items []feed.Item
	for _, it := range fetched {
		if st.Digested(it) {
			slog.Debug("already digested", "title", it.Title, "keys", it.Keys)
			continue
		}
		items = append(items, it)
	}
	slog.Info("dropped already digested items", "fetched", len(fetched),
		"already_digested", len(fetched)-len(items), "new", len(items))

	var findings, skipped []analyzer.Finding
	if len(items) == 0 {
		slog.Info("no new items in the fetch window, skipping analysis")
	} else {
		slog.Info("filtering items with claude", "items", len(items))
		t := time.Now()
		rated, err := a.Analyzer.Filter(ctx, items, a.Env)
		if err != nil {
			return errors.Join(append(errs, fmt.Errorf("filtering items: %w", err))...)
		}
		for _, f := range rated {
			if f.Relevance == analyzer.NotRelevant {
				skipped = append(skipped, f)
			} else {
				findings = append(findings, f)
			}
		}
		slog.Info("filtered items", "relevant", len(findings), "skipped", len(skipped), "duration", time.Since(t).Round(time.Second))
	}
	for _, f := range skipped {
		slog.Debug("skipped item", "title", f.Item.Title, "reason", f.Summary)
	}
	for _, f := range findings {
		slog.Info("relevant item", "relevance", f.Relevance, "title", f.Item.Title, "affected", f.Affected)
		slog.Debug("relevant item details", "title", f.Item.Title, "feed", f.Item.FeedTitle, "link", f.Item.Link)
	}

	// Only findings with a relevance listed in research_relevance are
	// researched. A failed research call keeps the unresearched finding in
	// the digest.
	var toResearch []int
	for i, f := range findings {
		if !slices.Contains(a.Env.ResearchRelevance, f.Relevance) {
			slog.Debug("skipping research", "title", f.Item.Title, "relevance", f.Relevance)
			continue
		}
		toResearch = append(toResearch, i)
	}
	if len(toResearch) > 0 {
		slog.Info("researching findings", "count", len(toResearch), "relevance", a.Env.ResearchRelevance)
	}

	researchFailed := 0
	for n, i := range toResearch {
		f := findings[i]
		progress := fmt.Sprintf("%d/%d", n+1, len(toResearch))
		slog.Info("researching finding", "progress", progress, "relevance", f.Relevance, "title", f.Item.Title)
		t := time.Now()
		researched, err := a.Analyzer.Research(ctx, f, a.Env)
		if err != nil {
			slog.Warn("researching finding failed", "progress", progress, "title", f.Item.Title,
				"duration", time.Since(t).Round(time.Second), "err", err)
			errs = append(errs, err)
			researchFailed++
			continue
		}
		slog.Info("researched finding", "progress", progress, "title", f.Item.Title,
			"references", len(researched.References), "duration", time.Since(t).Round(time.Second))
		findings[i] = researched
	}

	d := digest.Digest{
		GeneratedAt: time.Now(),
		ItemsSeen:   len(items),
		Findings:    findings,
		Skipped:     skipped,
	}

	delivered, err := notify.SendAll(ctx, a.Notifiers, d)
	if err != nil {
		errs = append(errs, err)
	}
	if err := a.record(st, start, items, delivered); err != nil {
		errs = append(errs, err)
	}

	slog.Info("run finished", "items", len(items), "findings", len(findings),
		"researched", len(toResearch)-researchFailed, "research_failed", researchFailed,
		"errors", len(errs), "duration", time.Since(start).Round(time.Second))
	return errors.Join(errs...)
}

// record saves the run in the state once at least one notifier delivered
// its digest: the run's start moves the next fetch window forward, and its
// items won't be digested again. A dry run never writes the state.
func (a *App) record(st *state.State, start time.Time, items []feed.Item, delivered int) error {
	switch {
	case a.DryRun:
		slog.Debug("dry run, not saving the state")
		return nil
	case delivered == 0:
		slog.Warn("digest was not delivered, not saving the state; the next run fetches the same window again")
		return nil
	}
	for _, it := range items {
		st.Add(it)
	}
	st.LastRun = start
	st.Prune(start.Add(-a.Config.MaxWindow))
	if err := st.Save(a.Config.StateFile); err != nil {
		return err
	}
	slog.Debug("saved state", "path", a.Config.StateFile, "items", len(st.Items))
	return nil
}

// fetch reads the RSS feeds and runs the advisory queries, and returns their
// items merged newest first. When one of the two fails completely, its error
// is returned in errs and the run goes on with the other; err is set when
// nothing could be fetched.
func (a *App) fetch(ctx context.Context, since time.Time) (items []feed.Item, errs []error, err error) {
	sources := 0
	if len(a.Env.Feeds) > 0 {
		sources++
		start := time.Now()
		got, err := feed.Fetch(ctx, a.Env.Feeds, since)
		if err != nil {
			errs = append(errs, fmt.Errorf("fetching feeds: %w", err))
		} else {
			slog.Info("fetched feeds", "feeds", len(a.Env.Feeds), "items", len(got), "since", since.Format(time.RFC3339),
				"duration", time.Since(start).Round(time.Millisecond))
			items = append(items, got...)
		}
	}
	if n := a.Env.Advisories.Len(); n > 0 {
		sources++
		start := time.Now()
		got, err := a.Advisories.Fetch(ctx, a.Env.Advisories, since)
		if err != nil {
			errs = append(errs, fmt.Errorf("fetching advisories: %w", err))
		} else {
			slog.Info("fetched advisories", "queries", n, "items", len(got), "since", since.Format(time.RFC3339),
				"duration", time.Since(start).Round(time.Millisecond))
			items = append(items, got...)
		}
	}

	switch {
	case sources == 0:
		return nil, nil, errors.New("no sources: add feeds or advisories to the environment file")
	case len(errs) == sources:
		return nil, nil, errors.Join(errs...)
	}
	for _, err := range errs {
		slog.Warn("continuing without a failed source", "err", err)
	}

	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Published.After(items[j].Published)
	})
	return items, errs, nil
}
