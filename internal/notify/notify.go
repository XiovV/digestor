// Package notify delivers a digest to one or more destinations.
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/XiovV/digestor/internal/config"
	"github.com/XiovV/digestor/internal/digest"
)

type Notifier interface {
	Name() string
	Send(ctx context.Context, d digest.Digest) error
}

// FromConfig returns a notifier for every destination configured in cfg.
func FromConfig(cfg *config.Config) []Notifier {
	var ns []Notifier
	if cfg.SMTP.Enabled() {
		ns = append(ns, &Email{cfg: cfg.SMTP})
	}
	if cfg.Discord.Enabled() {
		ns = append(ns, &Discord{cfg: cfg.Discord})
	}
	if cfg.Gotify.Enabled() {
		ns = append(ns, &Gotify{cfg: cfg.Gotify})
	}
	return ns
}

// SendAll sends d through every notifier and returns how many delivered it.
// A failure in one does not stop the others; all errors are returned joined.
func SendAll(ctx context.Context, ns []Notifier, d digest.Digest) (delivered int, err error) {
	var errs []error
	for _, n := range ns {
		slog.Debug("sending digest", "notifier", n.Name(), "findings", len(d.Findings))
		start := time.Now()
		if err := n.Send(ctx, d); err != nil {
			slog.Error("sending digest failed", "notifier", n.Name(), "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", n.Name(), err))
			continue
		}
		slog.Info("digest sent", "notifier", n.Name(), "duration", time.Since(start).Round(time.Millisecond))
		delivered++
	}
	return delivered, errors.Join(errs...)
}
