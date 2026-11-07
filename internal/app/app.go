// Package app wires the pipeline: fetch → filter → research → notify.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/XiovV/digestor/internal/analyzer"
	"github.com/XiovV/digestor/internal/config"
	"github.com/XiovV/digestor/internal/digest"
	"github.com/XiovV/digestor/internal/environment"
	"github.com/XiovV/digestor/internal/feed"
	"github.com/XiovV/digestor/internal/notify"
)

type App struct {
	Config    *config.Config
	Env       *environment.Environment
	Analyzer  analyzer.Analyzer
	Notifiers []notify.Notifier
}

func (a *App) Run(ctx context.Context) error {
	start := time.Now()
	since := start.Add(-a.Config.Lookback)

	names := make([]string, len(a.Notifiers))
	for i, n := range a.Notifiers {
		names[i] = n.Name()
	}
	slog.Info("starting run", "feeds", len(a.Config.Feeds), "lookback", a.Config.Lookback, "notifiers", names)

	items, err := feed.Fetch(ctx, a.Config.Feeds, since)
	if err != nil {
		return fmt.Errorf("fetching feeds: %w", err)
	}
	slog.Info("fetched feeds", "feeds", len(a.Config.Feeds), "items", len(items), "since", since.Format(time.RFC3339),
		"duration", time.Since(start).Round(time.Millisecond))

	var findings []analyzer.Finding
	if len(items) == 0 {
		slog.Info("no items in the lookback window, skipping analysis")
	} else {
		slog.Info("filtering items with claude", "items", len(items))
		t := time.Now()
		findings, err = a.Analyzer.Filter(ctx, items, a.Env)
		if err != nil {
			return fmt.Errorf("filtering items: %w", err)
		}
		slog.Info("filtered items", "relevant", len(findings), "duration", time.Since(t).Round(time.Second))
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

	var errs []error
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
	}

	if err := notify.SendAll(ctx, a.Notifiers, d); err != nil {
		errs = append(errs, err)
	}

	slog.Info("run finished", "items", len(items), "findings", len(findings),
		"researched", len(toResearch)-researchFailed, "research_failed", researchFailed,
		"errors", len(errs), "duration", time.Since(start).Round(time.Second))
	return errors.Join(errs...)
}
