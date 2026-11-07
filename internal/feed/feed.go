// Package feed fetches RSS/Atom/JSON feeds and normalises their items.
package feed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/mmcdole/gofeed"
)

type Item struct {
	FeedTitle string
	Title     string
	Link      string
	Summary   string
	GUID      string
	Published time.Time
}

// Fetch retrieves all feeds concurrently and returns the items published
// after since, newest first. A failing feed is logged and skipped; an error
// is returned only if every feed failed.
func Fetch(ctx context.Context, urls []string, since time.Time) ([]Item, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		items []Item
		errs  []error
	)

	for _, url := range urls {
		wg.Go(func() {
			got, err := fetchOne(ctx, url, since)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				slog.Warn("fetching feed failed", "url", url, "err", err)
				errs = append(errs, err)
				return
			}
			items = append(items, got...)
		})
	}
	wg.Wait()

	if len(errs) == len(urls) {
		return nil, fmt.Errorf("all feeds failed: %w", errors.Join(errs...))
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Published.After(items[j].Published)
	})
	return items, nil
}

func fetchOne(ctx context.Context, url string, since time.Time) ([]Item, error) {
	slog.Debug("fetching feed", "url", url)
	start := time.Now()
	f, err := gofeed.NewParser().ParseURLWithContext(url, ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}

	var items []Item
	undated := 0
	for _, it := range f.Items {
		published := itemTime(it)
		if published.IsZero() {
			undated++
			continue
		}
		if published.Before(since) {
			continue
		}

		items = append(items, Item{
			FeedTitle: f.Title,
			Title:     it.Title,
			Link:      it.Link,
			Summary:   it.Description,
			GUID:      it.GUID,
			Published: published,
		})
	}

	slog.Debug("fetched feed", "url", url, "title", f.Title, "total", len(f.Items), "in_window", len(items),
		"undated", undated, "duration", time.Since(start).Round(time.Millisecond))
	return items, nil
}

func itemTime(it *gofeed.Item) time.Time {
	switch {
	case it.PublishedParsed != nil:
		return *it.PublishedParsed
	case it.UpdatedParsed != nil:
		return *it.UpdatedParsed
	default:
		return time.Time{}
	}
}
