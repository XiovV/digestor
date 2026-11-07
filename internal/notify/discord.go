package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/XiovV/digestor/internal/config"
	"github.com/XiovV/digestor/internal/digest"
)

// discordMaxLen is Discord's message content limit, in characters.
const discordMaxLen = 2000

var httpClient = &http.Client{Timeout: 30 * time.Second}

// Discord posts the digest to a channel webhook.
type Discord struct {
	cfg config.Discord
}

func (n *Discord) Name() string { return "discord" }

// Send posts the digest as one or more messages. It stops at the first chunk
// that fails so the channel never gets a digest with a gap in it.
func (n *Discord) Send(ctx context.Context, d digest.Digest) error {
	chunks := splitMessage(d.Markdown(), discordMaxLen)
	for i, c := range chunks {
		slog.Debug("posting discord message", "chunk", fmt.Sprintf("%d/%d", i+1, len(chunks)), "chars", utf8.RuneCountInString(c))
		if err := n.post(ctx, c); err != nil {
			return fmt.Errorf("chunk %d/%d: %w", i+1, len(chunks), err)
		}
	}
	return nil
}

type discordMessage struct {
	Content         string                 `json:"content"`
	AllowedMentions discordAllowedMentions `json:"allowed_mentions"`
}

// discordAllowedMentions with an empty Parse stops feed text such as
// @everyone from pinging anyone.
type discordAllowedMentions struct {
	Parse []string `json:"parse"`
}

// post sends one message, retrying once if Discord rate limits it.
func (n *Discord) post(ctx context.Context, content string) error {
	body, err := json.Marshal(discordMessage{
		Content:         content,
		AllowedMentions: discordAllowedMentions{Parse: []string{}},
	})
	if err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}

	for retried := false; ; retried = true {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.WebhookURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("creating request: %w", redactURL(err))
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("posting message: %w", redactURL(err))
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return nil
		case resp.StatusCode == http.StatusTooManyRequests && !retried:
			wait := retryAfter(resp.Header, respBody)
			slog.Warn("discord rate limited, retrying", "wait", wait)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		default:
			return fmt.Errorf("unexpected status %s: %s", resp.Status, snippet(respBody))
		}
	}
}

// retryAfter reads the wait from a 429 response: the JSON retry_after field
// (seconds, may be fractional), then the Retry-After header, then 1s.
func retryAfter(h http.Header, body []byte) time.Duration {
	var rl struct {
		RetryAfter float64 `json:"retry_after"`
	}
	if json.Unmarshal(body, &rl) == nil && rl.RetryAfter > 0 {
		return time.Duration(rl.RetryAfter * float64(time.Second))
	}
	if s, err := strconv.ParseFloat(h.Get("Retry-After"), 64); err == nil && s > 0 {
		return time.Duration(s * float64(time.Second))
	}
	return time.Second
}

// redactURL drops the request URL from net/http errors, since a webhook URL
// contains its token and errors end up in the logs.
func redactURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if utf8.RuneCountInString(s) > 200 {
		s = string([]rune(s)[:200]) + "…"
	}
	return s
}

// splitMessage splits s into chunks of at most max characters, breaking
// between lines where possible. Lines longer than max are split mid-line.
// Blank chunks are dropped, since Discord rejects empty content.
func splitMessage(s string, max int) []string {
	var chunks []string
	var cur strings.Builder
	curLen := 0

	flush := func() {
		if strings.TrimSpace(cur.String()) != "" {
			chunks = append(chunks, cur.String())
		}
		cur.Reset()
		curLen = 0
	}

	for _, line := range strings.SplitAfter(s, "\n") {
		n := utf8.RuneCountInString(line)
		if curLen+n > max {
			flush()
		}
		for n > max {
			r := []rune(line)
			cur.WriteString(string(r[:max]))
			flush()
			line = string(r[max:])
			n -= max
		}
		cur.WriteString(line)
		curLen += n
	}
	flush()
	return chunks
}
