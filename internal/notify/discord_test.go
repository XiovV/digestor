package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/XiovV/digestor/internal/analyzer"
	"github.com/XiovV/digestor/internal/config"
	"github.com/XiovV/digestor/internal/digest"
)

func TestSplitMessage(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want []string
	}{
		{"empty", "", 10, nil},
		{"blank", " \n\n", 10, nil},
		{"short", "hello\n", 10, []string{"hello\n"}},
		{"exact", "0123456789", 10, []string{"0123456789"}},
		{"line boundaries", "aaaa\nbbbb\ncccc\n", 10, []string{"aaaa\nbbbb\n", "cccc\n"}},
		{"long line", "0123456789abcde\nxy\n", 10, []string{"0123456789", "abcde\nxy\n"}},
		{"very long line", strings.Repeat("a", 25), 10, []string{strings.Repeat("a", 10), strings.Repeat("a", 10), strings.Repeat("a", 5)}},
		{"multibyte", "ššššš\nđđđđđ\n", 6, []string{"ššššš\n", "đđđđđ\n"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitMessage(tt.in, tt.max)
			if len(got) != len(tt.want) {
				t.Fatalf("splitMessage(%q) = %q, want %q", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("chunk %d = %q, want %q", i, got[i], tt.want[i])
				}
				if n := utf8.RuneCountInString(got[i]); n > tt.max {
					t.Errorf("chunk %d has %d characters, max %d", i, n, tt.max)
				}
			}
		})
	}
}

func TestSplitMessageRoundTrip(t *testing.T) {
	in := testDigest(40).Markdown()
	chunks := splitMessage(in, discordMaxLen)
	if len(chunks) < 2 {
		t.Fatalf("got %d chunks, want several", len(chunks))
	}
	for i, c := range chunks {
		if n := utf8.RuneCountInString(c); n > discordMaxLen {
			t.Errorf("chunk %d has %d characters", i, n)
		}
	}
	if got := strings.Join(chunks, ""); got != in {
		t.Errorf("joined chunks differ from input")
	}
}

func TestDiscordSend(t *testing.T) {
	tests := []struct {
		name     string
		statuses []int // response per request; 204 once exhausted
		body     string
		wantErr  bool
		wantReqs int
	}{
		{"ok", nil, "", false, -1},
		{"bad request", []int{http.StatusBadRequest}, `{"message": "Cannot send an empty message"}`, true, 1},
		{"rate limited once", []int{http.StatusTooManyRequests}, `{"retry_after": 0.01}`, false, -1},
		{"rate limited twice", []int{http.StatusTooManyRequests, http.StatusTooManyRequests}, `{"retry_after": 0.01}`, true, 2},
	}

	d := testDigest(40)
	chunks := splitMessage(d.Markdown(), discordMaxLen)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []discordMessage
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if ct := r.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q", ct)
				}
				var m discordMessage
				if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
					t.Errorf("decoding body: %v", err)
				}
				if m.AllowedMentions.Parse == nil {
					t.Error("allowed_mentions.parse not set")
				}
				got = append(got, m)

				status := http.StatusNoContent
				if n := len(got) - 1; n < len(tt.statuses) {
					status = tt.statuses[n]
				}
				w.WriteHeader(status)
				if status != http.StatusNoContent {
					w.Write([]byte(tt.body))
				}
			}))
			defer srv.Close()

			n := &Discord{cfg: config.Discord{WebhookURL: srv.URL}}
			err := n.Send(context.Background(), d)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Send() error = %v, wantErr %v", err, tt.wantErr)
			}

			want := tt.wantReqs
			if want < 0 {
				want = len(chunks) + len(tt.statuses)
			}
			if len(got) != want {
				t.Fatalf("got %d requests, want %d", len(got), want)
			}
			if tt.wantErr {
				return
			}

			var contents []string
			for _, m := range got[len(tt.statuses):] {
				contents = append(contents, m.Content)
			}
			if strings.Join(contents, "") != d.Markdown() {
				t.Error("posted messages don't add up to the digest")
			}
		})
	}
}

func TestDiscordSendRedactsURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL + "/api/webhooks/1/secret-token"
	srv.Close()

	n := &Discord{cfg: config.Discord{WebhookURL: url}}
	err := n.Send(context.Background(), testDigest(1))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Errorf("error leaks the webhook URL: %v", err)
	}
}

func testDigest(n int) digest.Digest {
	d := digest.Digest{GeneratedAt: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), ItemsSeen: n}
	for i := range n {
		var f analyzer.Finding
		f.Relevance = "high"
		f.Item.Title = "Critical flaw in nginx"
		f.Item.Link = "https://example.com/story"
		f.Affected = []string{"nginx"}
		f.Summary = strings.Repeat("Attackers can exploit this remotely. ", 3+i%4)
		d.Findings = append(d.Findings, f)
	}
	return d
}
