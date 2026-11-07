// Package analyzer asks Claude which news items matter for an environment
// and researches the ones that do.
package analyzer

import (
	"context"

	"github.com/XiovV/digestor/internal/environment"
	"github.com/XiovV/digestor/internal/feed"
)

// NotRelevant is the relevance of an item Claude skipped. Its Summary holds
// the reason, or is empty when Claude did not mention the item.
const NotRelevant = "none"

type Finding struct {
	Item       feed.Item
	Relevance  string   // critical, high, medium, low or NotRelevant
	Affected   []string // components from the environment that match
	Summary    string
	Research   string // filled by Research
	References []string
}

type Analyzer interface {
	// Filter rates every item against env and returns one finding per item;
	// items that don't matter have relevance NotRelevant. It runs once over
	// the whole batch without tool access.
	Filter(ctx context.Context, items []feed.Item, env *environment.Environment) ([]Finding, error)

	// Research enriches a single finding using online sources.
	Research(ctx context.Context, f Finding, env *environment.Environment) (Finding, error)
}
