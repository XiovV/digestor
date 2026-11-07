// Package advisory fetches vulnerability advisories from the GitHub Advisory
// Database and OSV.dev and turns them into feed items.
package advisory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/XiovV/digestor/internal/environment"
	"github.com/XiovV/digestor/internal/feed"
)

const (
	defaultGitHubURL = "https://api.github.com"
	defaultOSVURL    = "https://api.osv.dev"
	userAgent        = "digestor"

	// maxPages caps the requests per query.
	maxPages = 10
	// maxDescription caps the description in an item's summary, in
	// characters, to keep the filter prompt small.
	maxDescription = 1500
)

// Client runs advisory queries. The zero value uses the public APIs without
// a GitHub token.
type Client struct {
	HTTP      *http.Client // defaults to one with a 30s timeout
	Token     string       // optional GitHub token
	GitHubURL string       // defaults to https://api.github.com
	OSVURL    string       // defaults to https://api.osv.dev
}

// advisory is a GitHub or OSV record reduced to what an item needs.
type advisory struct {
	ids         []string // primary ID first, then aliases
	title       string
	link        string
	severity    string
	affected    []string // one line per package
	description string
	published   time.Time
	withdrawn   bool
}

type query struct {
	label  string // for logs and errors
	source string // the item's FeedTitle
	fetch  func(ctx context.Context) ([]advisory, error)
}

// Fetch runs every query concurrently and returns the advisories published
// after since, newest first. Withdrawn advisories are dropped, and an
// advisory that shares an ID or alias with an earlier one is skipped:
// github queries come first, then github_repos, then osv. A failing query is
// logged and skipped; an error is returned only if every query failed.
func (c *Client) Fetch(ctx context.Context, q environment.Advisories, since time.Time) ([]feed.Item, error) {
	queries := c.queries(q, since)
	if len(queries) == 0 {
		return nil, nil
	}

	var (
		wg      sync.WaitGroup
		results = make([][]advisory, len(queries))
		errs    = make([]error, len(queries))
	)
	for i, qu := range queries {
		wg.Go(func() {
			start := time.Now()
			got, err := qu.fetch(ctx)
			if err != nil {
				slog.Warn("advisory query failed", "query", qu.label, "err", err)
				errs[i] = fmt.Errorf("%s: %w", qu.label, err)
				return
			}
			slog.Debug("ran advisory query", "query", qu.label, "advisories", len(got),
				"duration", time.Since(start).Round(time.Millisecond))
			results[i] = got
		})
	}
	wg.Wait()

	failed := 0
	for _, err := range errs {
		if err != nil {
			failed++
		}
	}
	if failed == len(queries) {
		return nil, fmt.Errorf("all advisory queries failed: %w", errors.Join(errs...))
	}

	seen := map[string]bool{}
	var items []feed.Item
	for i, advs := range results {
		for _, a := range advs {
			if a.withdrawn || a.published.Before(since) {
				continue
			}
			dup := slices.ContainsFunc(a.ids, func(id string) bool { return seen[id] })
			for _, id := range a.ids {
				seen[id] = true
			}
			if !dup {
				items = append(items, a.item(queries[i].source))
			}
		}
	}

	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Published.After(items[j].Published)
	})
	return items, nil
}

func (c *Client) queries(q environment.Advisories, since time.Time) []query {
	var out []query
	for _, gq := range q.GitHub {
		out = append(out, c.githubQuery(gq, since))
	}
	for _, repo := range q.GitHubRepos {
		out = append(out, c.repoQuery(repo, since))
	}
	for _, oq := range q.OSV {
		out = append(out, c.osvQuery(oq))
	}
	return out
}

func (a advisory) item(source string) feed.Item {
	var b strings.Builder
	fmt.Fprintf(&b, "IDs: %s\n", strings.Join(a.ids, ", "))
	if a.severity != "" {
		fmt.Fprintf(&b, "Severity: %s\n", a.severity)
	}
	for _, line := range a.affected {
		fmt.Fprintf(&b, "Affected: %s\n", line)
	}
	b.WriteString(truncate(strings.TrimSpace(a.description), maxDescription))

	title := a.title
	if title == "" {
		title = a.ids[0]
	}
	return feed.Item{
		FeedTitle: source,
		Title:     title,
		Link:      a.link,
		Summary:   strings.TrimSpace(b.String()),
		GUID:      a.ids[0],
		Published: a.published,
		Keys:      a.ids,
	}
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// statusError describes a non-2xx response, including the start of its body.
func statusError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return fmt.Errorf("%s %s: %s", resp.Request.Method, resp.Request.URL.Path, resp.Status)
	}
	return fmt.Errorf("%s %s: %s: %s", resp.Request.Method, resp.Request.URL.Path, resp.Status, msg)
}

// truncate cuts s to n characters, marking the cut with an ellipsis.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// unique returns the non-empty values of ss in order, without repeats.
func unique(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func withName(source, name string) string {
	if name == "" {
		return source
	}
	return fmt.Sprintf("%s (%s)", source, name)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
