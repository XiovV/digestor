package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/XiovV/digestor/internal/environment"
	"github.com/XiovV/digestor/internal/feed"
)

var since = time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)

// newServer serves routes (Go 1.22 mux patterns) and fails the test on any
// other request.
func newServer(t *testing.T, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for pattern, h := range routes {
		mux.HandleFunc(pattern, h)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newClient(srv *httptest.Server) *Client {
	return &Client{GitHubURL: srv.URL, OSVURL: srv.URL}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Error(err)
	}
}

// ghsa returns a minimal advisory as both GitHub endpoints return it.
func ghsa(id, published string) map[string]any {
	return map[string]any{
		"ghsa_id":         id,
		"cve_id":          nil,
		"html_url":        "https://github.com/advisories/" + id,
		"summary":         "Summary of " + id,
		"description":     "Description of " + id,
		"severity":        "medium",
		"identifiers":     []any{map[string]any{"type": "GHSA", "value": id}},
		"published_at":    published,
		"withdrawn_at":    nil,
		"vulnerabilities": []any{},
	}
}

// osvVuln returns a minimal OSV record.
func osvVuln(id, published string, aliases ...string) map[string]any {
	return map[string]any{
		"id":        id,
		"aliases":   aliases,
		"summary":   "Summary of " + id,
		"details":   "Details of " + id,
		"published": published,
		"modified":  published,
		"affected":  []any{},
	}
}

func guids(items []feed.Item) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.GUID)
	}
	return out
}

func TestFetchGitHubRequest(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		query     environment.GitHubQuery
		wantQuery url.Values
		wantAuth  string
	}{
		{
			name:  "minimal",
			query: environment.GitHubQuery{Affects: []string{"github.com/caddyserver/caddy/v2"}},
			wantQuery: url.Values{
				"affects":   {"github.com/caddyserver/caddy/v2"},
				"published": {">=2026-11-06T00:00:00Z"},
				"per_page":  {"100"},
			},
		},
		{
			name:  "all filters with token",
			token: "ghp_test",
			query: environment.GitHubQuery{
				Name:      "Caddy",
				Ecosystem: "go",
				Affects:   []string{"github.com/caddyserver/caddy/v2@2.11.2", "golang.org/x/net"},
				Severity:  "high",
				Type:      "reviewed",
				CWEs:      []string{"CWE-79", "CWE-89"},
			},
			wantQuery: url.Values{
				"ecosystem": {"go"},
				"affects":   {"github.com/caddyserver/caddy/v2@2.11.2,golang.org/x/net"},
				"severity":  {"high"},
				"type":      {"reviewed"},
				"cwes":      {"CWE-79,CWE-89"},
				"published": {">=2026-11-06T00:00:00Z"},
				"per_page":  {"100"},
			},
			wantAuth: "Bearer ghp_test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			srv := newServer(t, map[string]http.HandlerFunc{
				"GET /advisories": func(w http.ResponseWriter, r *http.Request) {
					requests++
					if got := r.URL.Query(); !reflect.DeepEqual(got, tt.wantQuery) {
						t.Errorf("query = %v, want %v", got, tt.wantQuery)
					}
					checkGitHubHeaders(t, r, tt.wantAuth)
					writeJSON(t, w, []any{})
				},
			})

			c := newClient(srv)
			c.Token = tt.token
			if _, err := c.Fetch(context.Background(), environment.Advisories{GitHub: []environment.GitHubQuery{tt.query}}, since); err != nil {
				t.Fatalf("Fetch() error = %v", err)
			}
			if requests != 1 {
				t.Errorf("got %d requests, want 1", requests)
			}
		})
	}
}

func checkGitHubHeaders(t *testing.T, r *http.Request, wantAuth string) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != wantAuth {
		t.Errorf("Authorization = %q, want %q", got, wantAuth)
	}
	if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
		t.Errorf("Accept = %q", got)
	}
	if got := r.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version = %q", got)
	}
	if got := r.Header.Get("User-Agent"); got != "digestor" {
		t.Errorf("User-Agent = %q", got)
	}
}

func TestFetchGitHubPagination(t *testing.T) {
	var srv *httptest.Server
	srv = newServer(t, map[string]http.HandlerFunc{
		"GET /advisories": func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Query().Get("after") {
			case "":
				w.Header().Set("Link", fmt.Sprintf(`<%s/advisories?per_page=100&after=c2>; rel="next"`, srv.URL))
				writeJSON(t, w, []any{ghsa("GHSA-1111-1111-1111", "2026-11-06T12:00:00Z")})
			case "c2":
				writeJSON(t, w, []any{ghsa("GHSA-2222-2222-2222", "2026-11-06T10:00:00Z")})
			default:
				t.Errorf("unexpected cursor %q", r.URL.Query().Get("after"))
			}
		},
	})

	items, err := newClient(srv).Fetch(context.Background(), environment.Advisories{
		GitHub: []environment.GitHubQuery{{Ecosystem: "go"}},
	}, since)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	want := []string{"GHSA-1111-1111-1111", "GHSA-2222-2222-2222"}
	if got := guids(items); !slices.Equal(got, want) {
		t.Errorf("GUIDs = %q, want %q", got, want)
	}
}

func TestFetchGitHubPageCap(t *testing.T) {
	var srv *httptest.Server
	requests := 0
	srv = newServer(t, map[string]http.HandlerFunc{
		"GET /advisories": func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.Header().Set("Link", fmt.Sprintf(`<%s/advisories?after=c%d>; rel="next"`, srv.URL, requests))
			writeJSON(t, w, []any{ghsa(fmt.Sprintf("GHSA-%04d-0000-0000", requests), "2026-11-06T12:00:00Z")})
		},
	})

	items, err := newClient(srv).Fetch(context.Background(), environment.Advisories{
		GitHub: []environment.GitHubQuery{{Ecosystem: "go"}},
	}, since)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if requests != 10 || len(items) != 10 {
		t.Errorf("got %d requests and %d items, want 10 of each", requests, len(items))
	}
}

func TestFetchGitHubRepo(t *testing.T) {
	var srv *httptest.Server
	srv = newServer(t, map[string]http.HandlerFunc{
		"GET /repos/caddyserver/caddy/security-advisories": func(w http.ResponseWriter, r *http.Request) {
			want := url.Values{
				"state":     {"published"},
				"sort":      {"published"},
				"direction": {"desc"},
				"per_page":  {"100"},
			}
			if got := r.URL.Query(); !reflect.DeepEqual(got, want) {
				t.Errorf("query = %v, want %v (a page past the lookback window was requested?)", got, want)
			}
			checkGitHubHeaders(t, r, "")
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/caddyserver/caddy/security-advisories?after=c2>; rel="next"`, srv.URL))
			writeJSON(t, w, []any{
				ghsa("GHSA-jf74-f69g-hcj9", "2026-11-06T08:00:00Z"),
				ghsa("GHSA-r766-rf9f-588h", "2026-11-05T23:00:00Z"),
			})
		},
	})

	items, err := newClient(srv).Fetch(context.Background(), environment.Advisories{
		GitHubRepos: []string{"caddyserver/caddy"},
	}, since)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	want := []string{"GHSA-jf74-f69g-hcj9"}
	if got := guids(items); !slices.Equal(got, want) {
		t.Errorf("GUIDs = %q, want %q", got, want)
	}
}

func TestFetchOSVRequest(t *testing.T) {
	tests := []struct {
		name  string
		query environment.OSVQuery
		want  map[string]any
	}{
		{
			name:  "package and version",
			query: environment.OSVQuery{Name: "Go", Ecosystem: "Go", Package: "stdlib", Version: "1.23.0"},
			want: map[string]any{
				"package": map[string]any{"ecosystem": "Go", "name": "stdlib"},
				"version": "1.23.0",
			},
		},
		{
			name:  "package only",
			query: environment.OSVQuery{Ecosystem: "Go", Package: "stdlib"},
			want:  map[string]any{"package": map[string]any{"ecosystem": "Go", "name": "stdlib"}},
		},
		{
			name:  "purl",
			query: environment.OSVQuery{PURL: "pkg:golang/stdlib"},
			want:  map[string]any{"package": map[string]any{"purl": "pkg:golang/stdlib"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			srv := newServer(t, map[string]http.HandlerFunc{
				"POST /v1/query": func(w http.ResponseWriter, r *http.Request) {
					requests++
					if ct := r.Header.Get("Content-Type"); ct != "application/json" {
						t.Errorf("Content-Type = %q", ct)
					}
					var got map[string]any
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Errorf("decoding body: %v", err)
					}
					if !reflect.DeepEqual(got, tt.want) {
						t.Errorf("body = %v, want %v", got, tt.want)
					}
					// OSV answers {} when nothing matches.
					writeJSON(t, w, map[string]any{})
				},
			})

			items, err := newClient(srv).Fetch(context.Background(), environment.Advisories{OSV: []environment.OSVQuery{tt.query}}, since)
			if err != nil {
				t.Fatalf("Fetch() error = %v", err)
			}
			if requests != 1 || len(items) != 0 {
				t.Errorf("got %d requests and %d items, want 1 and 0", requests, len(items))
			}
		})
	}
}

func TestFetchOSVPagination(t *testing.T) {
	srv := newServer(t, map[string]http.HandlerFunc{
		"POST /v1/query": func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decoding body: %v", err)
			}
			if body["package"] == nil {
				t.Errorf("body %v has no package", body)
			}
			switch body["page_token"] {
			case nil:
				writeJSON(t, w, map[string]any{
					"vulns":           []any{osvVuln("GO-2026-0001", "2026-11-06T12:00:00Z")},
					"next_page_token": "t1",
				})
			case "t1":
				writeJSON(t, w, map[string]any{"vulns": []any{osvVuln("GO-2026-0002", "2026-11-06T10:00:00Z")}})
			default:
				t.Errorf("unexpected page_token %v", body["page_token"])
			}
		},
	})

	items, err := newClient(srv).Fetch(context.Background(), environment.Advisories{
		OSV: []environment.OSVQuery{{PURL: "pkg:golang/stdlib"}},
	}, since)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	want := []string{"GO-2026-0001", "GO-2026-0002"}
	if got := guids(items); !slices.Equal(got, want) {
		t.Errorf("GUIDs = %q, want %q", got, want)
	}
}

// TestFetchMerges covers the lookback window, withdrawn advisories,
// duplicates across sources (the first source wins) and newest-first order.
func TestFetchMerges(t *testing.T) {
	withCVE := ghsa("GHSA-aaaa-aaaa-aaaa", "2026-11-06T12:00:00Z")
	withCVE["cve_id"] = "CVE-2026-0001"
	withdrawn := ghsa("GHSA-wwww-wwww-wwww", "2026-11-06T11:00:00Z")
	withdrawn["withdrawn_at"] = "2026-11-06T11:30:00Z"
	osvWithdrawn := osvVuln("GO-2026-0004", "2026-11-06T14:00:00Z")
	osvWithdrawn["withdrawn"] = "2026-11-06T15:00:00Z"

	srv := newServer(t, map[string]http.HandlerFunc{
		"GET /advisories": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(t, w, []any{withCVE, withdrawn})
		},
		"GET /repos/caddyserver/caddy/security-advisories": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(t, w, []any{
				withCVE,
				ghsa("GHSA-bbbb-bbbb-bbbb", "2026-11-06T09:00:00Z"),
				ghsa("GHSA-oooo-oooo-oooo", "2026-11-05T20:00:00Z"),
			})
		},
		"POST /v1/query": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(t, w, map[string]any{"vulns": []any{
				osvVuln("GO-2026-0001", "2026-11-06T13:00:00Z", "CVE-2026-0001"),
				osvVuln("GO-2026-0002", "2026-11-06T09:00:00Z", "GHSA-bbbb-bbbb-bbbb"),
				osvVuln("GO-2026-0003", "2026-11-06T10:00:00Z"),
				osvVuln("GO-2025-0001", "2025-01-01T00:00:00Z"),
				osvWithdrawn,
			}})
		},
	})

	items, err := newClient(srv).Fetch(context.Background(), environment.Advisories{
		GitHub:      []environment.GitHubQuery{{Ecosystem: "go"}},
		GitHubRepos: []string{"caddyserver/caddy"},
		OSV:         []environment.OSVQuery{{PURL: "pkg:golang/stdlib"}},
	}, since)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	want := []string{"GHSA-aaaa-aaaa-aaaa", "GO-2026-0003", "GHSA-bbbb-bbbb-bbbb"}
	if got := guids(items); !slices.Equal(got, want) {
		t.Errorf("GUIDs = %q, want %q", got, want)
	}
}

func TestFetchItems(t *testing.T) {
	tests := []struct {
		name    string
		query   environment.Advisories
		pattern string
		body    string
		want    feed.Item
	}{
		{
			name:    "global advisory",
			query:   environment.Advisories{GitHub: []environment.GitHubQuery{{Name: "Caddy", Ecosystem: "go"}}},
			pattern: "GET /advisories",
			body: `[{
				"ghsa_id": "GHSA-8qx7-j2v2-x6q5",
				"cve_id": "CVE-2026-55458",
				"html_url": "https://github.com/advisories/GHSA-8qx7-j2v2-x6q5",
				"summary": "Hop-by-hop headers leak through",
				"description": "Caddy forwards hop-by-hop headers.\n",
				"severity": "low",
				"identifiers": [{"value": "GHSA-8qx7-j2v2-x6q5", "type": "GHSA"}, {"value": "CVE-2026-55458", "type": "CVE"}],
				"published_at": "2026-11-06T19:49:33Z",
				"withdrawn_at": null,
				"vulnerabilities": [{
					"package": {"ecosystem": "go", "name": "github.com/caddyserver/caddy/v2"},
					"vulnerable_version_range": "<= 2.11.4",
					"first_patched_version": "2.11.5"
				}],
				"cvss_severities": {
					"cvss_v3": {"vector_string": null, "score": 0.0},
					"cvss_v4": {"vector_string": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", "score": 2.9}
				}
			}]`,
			want: feed.Item{
				FeedTitle: "GitHub Advisory Database (Caddy)",
				Title:     "Hop-by-hop headers leak through",
				Link:      "https://github.com/advisories/GHSA-8qx7-j2v2-x6q5",
				GUID:      "GHSA-8qx7-j2v2-x6q5",
				Published: time.Date(2026, 11, 6, 19, 49, 33, 0, time.UTC),
				Summary: "IDs: GHSA-8qx7-j2v2-x6q5, CVE-2026-55458\n" +
					"Severity: low (CVSS 2.9)\n" +
					"Affected: github.com/caddyserver/caddy/v2 <= 2.11.4, patched in 2.11.5\n" +
					"Caddy forwards hop-by-hop headers.",
			},
		},
		{
			name:    "repository advisory",
			query:   environment.Advisories{GitHubRepos: []string{"caddyserver/caddy"}},
			pattern: "GET /repos/caddyserver/caddy/security-advisories",
			body: `[{
				"ghsa_id": "GHSA-jf74-f69g-hcj9",
				"cve_id": null,
				"html_url": "https://github.com/caddyserver/caddy/security/advisories/GHSA-jf74-f69g-hcj9",
				"summary": "Path traversal in file_server",
				"description": "A crafted path escapes the root.",
				"severity": "high",
				"identifiers": [{"value": "GHSA-jf74-f69g-hcj9", "type": "GHSA"}],
				"published_at": "2026-11-06T01:11:26Z",
				"withdrawn_at": null,
				"vulnerabilities": [
					{"package": {"ecosystem": "go", "name": "github.com/caddyserver/caddy/v2"}, "vulnerable_version_range": ">= 2.4.6, <= 2.11.7", "patched_versions": "v2.11.8"},
					{"package": {"ecosystem": "go", "name": "github.com/caddyserver/caddy"}, "vulnerable_version_range": "<= 1.0.5", "patched_versions": null}
				],
				"cvss_severities": {
					"cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5},
					"cvss_v4": {"vector_string": null, "score": 0.0}
				}
			}]`,
			want: feed.Item{
				FeedTitle: "GitHub advisories: caddyserver/caddy",
				Title:     "Path traversal in file_server",
				Link:      "https://github.com/caddyserver/caddy/security/advisories/GHSA-jf74-f69g-hcj9",
				GUID:      "GHSA-jf74-f69g-hcj9",
				Published: time.Date(2026, 11, 6, 1, 11, 26, 0, time.UTC),
				Summary: "IDs: GHSA-jf74-f69g-hcj9\n" +
					"Severity: high (CVSS 7.5)\n" +
					"Affected: github.com/caddyserver/caddy/v2 >= 2.4.6, <= 2.11.7, patched in v2.11.8\n" +
					"Affected: github.com/caddyserver/caddy <= 1.0.5, no patch\n" +
					"A crafted path escapes the root.",
			},
		},
		{
			name:    "go vulnerability database entry",
			query:   environment.Advisories{OSV: []environment.OSVQuery{{Name: "Go", Ecosystem: "Go", Package: "stdlib"}}},
			pattern: "POST /v1/query",
			body: `{"vulns": [{
				"id": "GO-2024-3105",
				"aliases": ["CVE-2024-34155"],
				"summary": "Stack exhaustion in all Parse functions in go/parser",
				"details": "Calling any of the Parse functions on deeply nested input can exhaust the stack.",
				"published": "2026-11-06T15:00:00Z",
				"modified": "2026-11-06T15:00:00Z",
				"affected": [{
					"package": {"name": "stdlib", "ecosystem": "Go"},
					"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.22.7"}, {"introduced": "1.23.0-0"}, {"fixed": "1.23.1"}]}]
				}],
				"database_specific": {"url": "https://pkg.go.dev/vuln/GO-2024-3105"}
			}]}`,
			want: feed.Item{
				FeedTitle: "OSV (Go)",
				Title:     "Stack exhaustion in all Parse functions in go/parser",
				Link:      "https://osv.dev/vulnerability/GO-2024-3105",
				GUID:      "GO-2024-3105",
				Published: time.Date(2026, 11, 6, 15, 0, 0, 0, time.UTC),
				Summary: "IDs: GO-2024-3105, CVE-2024-34155\n" +
					"Affected: stdlib < 1.22.7; >= 1.23.0-0, < 1.23.1\n" +
					"Calling any of the Parse functions on deeply nested input can exhaust the stack.",
			},
		},
		{
			name:    "github record in osv",
			query:   environment.Advisories{OSV: []environment.OSVQuery{{PURL: "pkg:golang/github.com/caddyserver/caddy/v2"}}},
			pattern: "POST /v1/query",
			body: `{"vulns": [{
				"id": "GHSA-j8px-rmrx-76h9",
				"aliases": ["CVE-2026-77281", "GO-2026-6001"],
				"summary": "Unbounded body buffer",
				"details": "A large request body is buffered in memory.",
				"published": "2026-11-06T13:00:00Z",
				"modified": "2026-11-06T13:00:00Z",
				"affected": [{
					"package": {"name": "github.com/caddyserver/caddy/v2", "ecosystem": "Go"},
					"ranges": [
						{"type": "SEMVER", "events": [{"introduced": "2.4.6"}, {"last_affected": "2.11.7"}]},
						{"type": "GIT", "repo": "https://github.com/caddyserver/caddy", "events": [{"introduced": "abc123"}, {"fixed": "def456"}]}
					]
				}],
				"database_specific": {"severity": "MODERATE"}
			}]}`,
			want: feed.Item{
				FeedTitle: "OSV",
				Title:     "Unbounded body buffer",
				Link:      "https://osv.dev/vulnerability/GHSA-j8px-rmrx-76h9",
				GUID:      "GHSA-j8px-rmrx-76h9",
				Published: time.Date(2026, 11, 6, 13, 0, 0, 0, time.UTC),
				Summary: "IDs: GHSA-j8px-rmrx-76h9, CVE-2026-77281, GO-2026-6001\n" +
					"Severity: medium\n" +
					"Affected: github.com/caddyserver/caddy/v2 >= 2.4.6, <= 2.11.7\n" +
					"A large request body is buffered in memory.",
			},
		},
		{
			name:    "title falls back to id",
			query:   environment.Advisories{OSV: []environment.OSVQuery{{PURL: "pkg:golang/stdlib"}}},
			pattern: "POST /v1/query",
			body:    `{"vulns": [{"id": "GO-2026-0009", "details": "No summary.", "published": "2026-11-06T13:00:00Z"}]}`,
			want: feed.Item{
				FeedTitle: "OSV",
				Title:     "GO-2026-0009",
				Link:      "https://osv.dev/vulnerability/GO-2026-0009",
				GUID:      "GO-2026-0009",
				Published: time.Date(2026, 11, 6, 13, 0, 0, 0, time.UTC),
				Summary:   "IDs: GO-2026-0009\nNo summary.",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newServer(t, map[string]http.HandlerFunc{
				tt.pattern: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(tt.body))
				},
			})

			items, err := newClient(srv).Fetch(context.Background(), tt.query, since)
			if err != nil {
				t.Fatalf("Fetch() error = %v", err)
			}
			if len(items) != 1 {
				t.Fatalf("got %d items, want 1", len(items))
			}
			got := items[0]
			if !got.Published.Equal(tt.want.Published) {
				t.Errorf("Published = %v, want %v", got.Published, tt.want.Published)
			}
			got.Published, tt.want.Published = time.Time{}, time.Time{}
			if got != tt.want {
				t.Errorf("item =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

func TestFetchTruncatesDescription(t *testing.T) {
	a := ghsa("GHSA-1111-1111-1111", "2026-11-06T12:00:00Z")
	a["description"] = strings.Repeat("é", 2000)
	srv := newServer(t, map[string]http.HandlerFunc{
		"GET /advisories": func(w http.ResponseWriter, r *http.Request) { writeJSON(t, w, []any{a}) },
	})

	items, err := newClient(srv).Fetch(context.Background(), environment.Advisories{
		GitHub: []environment.GitHubQuery{{Ecosystem: "go"}},
	}, since)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	want := "\n" + strings.Repeat("é", 1500) + "…"
	if !strings.HasSuffix(items[0].Summary, want) || strings.Contains(items[0].Summary, strings.Repeat("é", 1501)) {
		t.Errorf("Summary does not end with 1500 characters of description and an ellipsis: %q", items[0].Summary[:80])
	}
}

func TestFetchFailures(t *testing.T) {
	ok := func(t *testing.T) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			writeJSON(t, w, []any{ghsa("GHSA-1111-1111-1111", "2026-11-06T12:00:00Z")})
		}
	}
	fail := func(t *testing.T) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}
	rateLimited := func(t *testing.T) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			http.Error(w, `{"message": "API rate limit exceeded"}`, http.StatusForbidden)
		}
	}
	both := environment.Advisories{
		GitHub: []environment.GitHubQuery{{Ecosystem: "go"}},
		OSV:    []environment.OSVQuery{{PURL: "pkg:golang/stdlib"}},
	}

	tests := []struct {
		name      string
		query     environment.Advisories
		github    func(*testing.T) http.HandlerFunc
		osv       func(*testing.T) http.HandlerFunc
		wantGUIDs []string
		wantErr   string // substring; empty means success
	}{
		{name: "one query fails", query: both, github: ok, osv: fail, wantGUIDs: []string{"GHSA-1111-1111-1111"}},
		{name: "every query fails", query: both, github: fail, osv: fail, wantErr: "500"},
		{
			name:    "rate limited",
			query:   environment.Advisories{GitHub: []environment.GitHubQuery{{Ecosystem: "go"}}},
			github:  rateLimited,
			wantErr: "GITHUB_TOKEN",
		},
		{name: "no queries"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := map[string]http.HandlerFunc{}
			if tt.github != nil {
				routes["GET /advisories"] = tt.github(t)
			}
			if tt.osv != nil {
				routes["POST /v1/query"] = tt.osv(t)
			}
			srv := newServer(t, routes)

			items, err := newClient(srv).Fetch(context.Background(), tt.query, since)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Fetch() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Fetch() error = %v", err)
			}
			if got := guids(items); !slices.Equal(got, tt.wantGUIDs) {
				t.Errorf("GUIDs = %q, want %q", got, tt.wantGUIDs)
			}
		})
	}
}
