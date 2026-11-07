// Package digest holds the final report and renders it for notifiers.
package digest

import (
	"fmt"
	"strings"
	"time"

	"github.com/XiovV/digestor/internal/analyzer"
)

type Digest struct {
	GeneratedAt time.Time
	ItemsSeen   int
	Findings    []analyzer.Finding
	Skipped     []analyzer.Finding // items Claude rated not relevant, with the reason in Summary
}

func (d Digest) Title() string {
	return fmt.Sprintf("Security digest %s: %d relevant of %d", d.GeneratedAt.Format("2006-01-02"), len(d.Findings), d.ItemsSeen)
}

// Markdown renders the digest for Discord, Gotify and stdout.
// TODO: sort by relevance and polish formatting.
func (d Digest) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", d.Title())

	if len(d.Findings) == 0 {
		b.WriteString("Nothing relevant to your environment.\n\n")
	}

	for _, f := range d.Findings {
		fmt.Fprintf(&b, "## [%s] %s\n", strings.ToUpper(f.Relevance), f.Item.Title)
		fmt.Fprintf(&b, "%s\n\n", f.Item.Link)
		if len(f.Affected) > 0 {
			fmt.Fprintf(&b, "**Affects:** %s\n\n", strings.Join(f.Affected, ", "))
		}
		fmt.Fprintf(&b, "%s\n\n", f.Summary)
		if f.Research != "" {
			fmt.Fprintf(&b, "%s\n\n", f.Research)
		}
		for _, ref := range f.References {
			fmt.Fprintf(&b, "- %s\n", ref)
		}
		b.WriteString("\n")
	}

	if len(d.Skipped) > 0 {
		fmt.Fprintf(&b, "## Not relevant (%d)\n", len(d.Skipped))
		for _, f := range d.Skipped {
			reason := f.Summary
			if reason == "" {
				reason = "no reason given"
			}
			fmt.Fprintf(&b, "- %s: %s\n", f.Item.Title, reason)
			// Angle brackets keep Discord from adding a preview for every link.
			if f.Item.Link != "" {
				fmt.Fprintf(&b, "  <%s>\n", f.Item.Link)
			}
		}
	}
	return b.String()
}

// Text renders the digest as plain text for email.
// TODO: implement properly, or send HTML email instead.
func (d Digest) Text() string {
	return d.Markdown()
}
