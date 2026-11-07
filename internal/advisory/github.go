package advisory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/XiovV/digestor/internal/environment"
)

// ghAdvisory is the shape both GET /advisories and the repository endpoint
// return. Only the global endpoint sets first_patched_version, and only the
// repository endpoint sets patched_versions.
type ghAdvisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	HTMLURL     string `json:"html_url"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Identifiers []struct {
		Value string `json:"value"`
	} `json:"identifiers"`
	PublishedAt     time.Time  `json:"published_at"`
	WithdrawnAt     *time.Time `json:"withdrawn_at"`
	Vulnerabilities []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    string `json:"first_patched_version"`
		PatchedVersions        string `json:"patched_versions"`
	} `json:"vulnerabilities"`
	CVSSSeverities struct {
		V3 struct {
			Score float64 `json:"score"`
		} `json:"cvss_v3"`
		V4 struct {
			Score float64 `json:"score"`
		} `json:"cvss_v4"`
	} `json:"cvss_severities"`
}

func (c *Client) githubQuery(q environment.GitHubQuery, since time.Time) query {
	v := url.Values{}
	setNonEmpty(v, "ecosystem", q.Ecosystem)
	setNonEmpty(v, "affects", strings.Join(q.Affects, ","))
	setNonEmpty(v, "severity", q.Severity)
	setNonEmpty(v, "type", q.Type)
	setNonEmpty(v, "cwes", strings.Join(q.CWEs, ","))
	v.Set("published", ">="+since.UTC().Format(time.RFC3339))
	v.Set("per_page", "100")

	u := c.githubURL() + "/advisories?" + v.Encode()
	label := "github: " + firstNonEmpty(q.Name, strings.Join(q.Affects, ","), q.Ecosystem, strings.Join(q.CWEs, ","))
	return query{
		label:  label,
		source: withName("GitHub Advisory Database", q.Name),
		fetch: func(ctx context.Context) ([]advisory, error) {
			return c.githubPages(ctx, u, time.Time{})
		},
	}
}

// repoQuery reads a repository's own advisories, newest first, and stops
// paging at the first one published before since.
func (c *Client) repoQuery(repo string, since time.Time) query {
	owner, name, _ := strings.Cut(repo, "/")
	u := fmt.Sprintf("%s/repos/%s/%s/security-advisories?direction=desc&per_page=100&sort=published&state=published",
		c.githubURL(), url.PathEscape(owner), url.PathEscape(name))
	return query{
		label:  "github_repos: " + repo,
		source: "GitHub advisories: " + repo,
		fetch: func(ctx context.Context) ([]advisory, error) {
			return c.githubPages(ctx, u, since)
		},
	}
}

// githubPages follows the Link header from u for up to maxPages pages. A
// non-zero stopBefore ends paging at the first advisory published before it.
func (c *Client) githubPages(ctx context.Context, u string, stopBefore time.Time) ([]advisory, error) {
	var out []advisory
	for range maxPages {
		var page []ghAdvisory
		next, err := c.getGitHub(ctx, u, &page)
		if err != nil {
			return nil, err
		}
		for _, a := range page {
			if !stopBefore.IsZero() && a.PublishedAt.Before(stopBefore) {
				return out, nil
			}
			out = append(out, a.advisory())
		}
		if next == "" {
			return out, nil
		}
		u = next
	}
	slog.Warn("stopped paging advisories", "pages", maxPages, "next", u)
	return out, nil
}

func (c *Client) getGitHub(ctx context.Context, u string, v any) (next string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", userAgent)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		limited := resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests
		if limited && resp.Header.Get("X-RateLimit-Remaining") == "0" {
			if c.Token == "" {
				return "", errors.New("GitHub API rate limit exceeded; set GITHUB_TOKEN for a higher limit")
			}
			return "", fmt.Errorf("GitHub API rate limit exceeded until %s", rateLimitReset(resp))
		}
		return "", statusError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return "", fmt.Errorf("decoding %s: %w", resp.Request.URL.Path, err)
	}
	return nextLink(resp.Header.Get("Link")), nil
}

func (a ghAdvisory) advisory() advisory {
	ids := []string{a.GHSAID, a.CVEID}
	for _, id := range a.Identifiers {
		ids = append(ids, id.Value)
	}

	severity := a.Severity
	score := a.CVSSSeverities.V4.Score
	if score == 0 {
		score = a.CVSSSeverities.V3.Score
	}
	if severity != "" && score > 0 {
		severity = fmt.Sprintf("%s (CVSS %.1f)", severity, score)
	}

	var affected []string
	for _, v := range a.Vulnerabilities {
		line := strings.TrimSpace(v.Package.Name + " " + v.VulnerableVersionRange)
		if patched := firstNonEmpty(v.FirstPatchedVersion, v.PatchedVersions); patched != "" {
			line += ", patched in " + patched
		} else {
			line += ", no patch"
		}
		affected = append(affected, line)
	}

	return advisory{
		ids:         unique(ids...),
		title:       a.Summary,
		link:        a.HTMLURL,
		severity:    severity,
		affected:    affected,
		description: a.Description,
		published:   a.PublishedAt,
		withdrawn:   a.WithdrawnAt != nil,
	}
}

func (c *Client) githubURL() string {
	return strings.TrimSuffix(firstNonEmpty(c.GitHubURL, defaultGitHubURL), "/")
}

// nextLink returns the rel="next" URL of a Link header, or "".
func nextLink(header string) string {
	for part := range strings.SplitSeq(header, ",") {
		target, params, ok := strings.Cut(part, ";")
		if ok && strings.Contains(params, `rel="next"`) {
			return strings.Trim(strings.TrimSpace(target), "<>")
		}
	}
	return ""
}

func rateLimitReset(resp *http.Response) string {
	var unix int64
	if _, err := fmt.Sscan(resp.Header.Get("X-RateLimit-Reset"), &unix); err != nil {
		return "the limit resets"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func setNonEmpty(v url.Values, key, value string) {
	if value != "" {
		v.Set(key, value)
	}
}
