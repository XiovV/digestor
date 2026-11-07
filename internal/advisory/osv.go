package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/XiovV/digestor/internal/environment"
)

type osvRequest struct {
	Package   osvPackage `json:"package"`
	Version   string     `json:"version,omitempty"`
	PageToken string     `json:"page_token,omitempty"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

type osvResponse struct {
	Vulns         []osvEntry `json:"vulns"`
	NextPageToken string     `json:"next_page_token"`
}

type osvEntry struct {
	ID        string     `json:"id"`
	Aliases   []string   `json:"aliases"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Published time.Time  `json:"published"`
	Withdrawn *time.Time `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	// DatabaseSpecific differs per database; only a string severity (set by
	// GitHub records) is used.
	DatabaseSpecific struct {
		Severity json.RawMessage `json:"severity"`
	} `json:"database_specific"`
}

func (c *Client) osvQuery(q environment.OSVQuery) query {
	req := osvRequest{
		Package: osvPackage{Ecosystem: q.Ecosystem, Name: q.Package, PURL: q.PURL},
		Version: q.Version,
	}
	return query{
		label:  "osv: " + firstNonEmpty(q.Name, q.PURL, q.Ecosystem+"/"+q.Package),
		source: withName("OSV", q.Name),
		fetch: func(ctx context.Context) ([]advisory, error) {
			return c.osvPages(ctx, req)
		},
	}
}

func (c *Client) osvPages(ctx context.Context, req osvRequest) ([]advisory, error) {
	var out []advisory
	for range maxPages {
		resp, err := c.postOSV(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, v := range resp.Vulns {
			out = append(out, v.advisory())
		}
		if resp.NextPageToken == "" {
			return out, nil
		}
		req.PageToken = resp.NextPageToken
	}
	slog.Warn("stopped paging advisories", "pages", maxPages, "package", req.Package)
	return out, nil
}

func (c *Client) postOSV(ctx context.Context, body osvRequest) (*osvResponse, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	u := strings.TrimSuffix(firstNonEmpty(c.OSVURL, defaultOSVURL), "/") + "/v1/query"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp)
	}
	var out osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", resp.Request.URL.Path, err)
	}
	return &out, nil
}

func (v osvEntry) advisory() advisory {
	var affected []string
	for _, a := range v.Affected {
		var ranges []string
		for _, r := range a.Ranges {
			// GIT ranges list commits, which don't help a reader.
			if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
				if s := osvRange(r.Events); s != "" {
					ranges = append(ranges, s)
				}
			}
		}
		affected = append(affected, strings.TrimSpace(a.Package.Name+" "+strings.Join(ranges, "; ")))
	}

	var severity string
	if json.Unmarshal(v.DatabaseSpecific.Severity, &severity) == nil {
		severity = strings.ToLower(severity)
		if severity == "moderate" {
			severity = "medium"
		}
	}

	return advisory{
		ids:         unique(append([]string{v.ID}, v.Aliases...)...),
		title:       v.Summary,
		link:        "https://osv.dev/vulnerability/" + v.ID,
		severity:    severity,
		affected:    affected,
		description: v.Details,
		published:   v.Published,
		withdrawn:   v.Withdrawn != nil,
	}
}

// osvRange renders range events such as introduced 0, fixed 1.22.7,
// introduced 1.23.0-0, fixed 1.23.1 as "< 1.22.7; >= 1.23.0-0, < 1.23.1".
func osvRange(events []map[string]string) string {
	var (
		parts []string
		cur   []string // bounds of the open interval; nil when none is open
	)
	closeWith := func(bound string) {
		parts = append(parts, strings.Join(append(cur, bound), ", "))
		cur = nil
	}
	for _, e := range events {
		switch {
		case e["introduced"] == "0":
			cur = []string{}
		case e["introduced"] != "":
			cur = []string{">= " + e["introduced"]}
		case e["fixed"] != "":
			closeWith("< " + e["fixed"])
		case e["last_affected"] != "":
			closeWith("<= " + e["last_affected"])
		}
	}
	switch {
	case cur == nil:
	case len(cur) == 0:
		parts = append(parts, "all versions")
	default:
		parts = append(parts, strings.Join(cur, ", "))
	}
	return strings.Join(parts, "; ")
}
