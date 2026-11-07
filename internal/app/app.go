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
	since := time.Now().Add(-a.Config.Lookback)

	items, err := feed.Fetch(ctx, a.Config.Feeds, since)
	if err != nil {
		return fmt.Errorf("fetching feeds: %w", err)
	}
	slog.Info("fetched feeds", "feeds", len(a.Config.Feeds), "items", len(items), "since", since.Format(time.RFC3339))

	findings, err := a.Analyzer.Filter(ctx, items, a.Env)
	if err != nil {
		return fmt.Errorf("filtering items: %w", err)
	}
	slog.Info("filtered items", "relevant", len(findings))

	// Only findings with a relevance listed in research_relevance are
	// researched. A failed research call keeps the unresearched finding in
	// the digest.
	var errs []error
	for i, f := range findings {
		if !slices.Contains(a.Env.ResearchRelevance, f.Relevance) {
			continue
		}
		researched, err := a.Analyzer.Research(ctx, f, a.Env)
		if err != nil {
			slog.Warn("researching finding failed", "title", f.Item.Title, "err", err)
			errs = append(errs, err)
			continue
		}
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
	return errors.Join(errs...)
}
