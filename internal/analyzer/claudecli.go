package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/XiovV/digestor/internal/environment"
	"github.com/XiovV/digestor/internal/feed"
)

var researchTools = []string{"WebSearch", "WebFetch"}

// ClaudeCLI implements Analyzer by running the Claude Code CLI in print mode.
type ClaudeCLI struct {
	Bin     string
	Model   string
	Timeout time.Duration
}

func (c *ClaudeCLI) Filter(ctx context.Context, items []feed.Item, env *environment.Environment) ([]Finding, error) {
	if len(items) == 0 {
		return nil, nil
	}

	prompt, err := filterPrompt(items, env)
	if err != nil {
		return nil, fmt.Errorf("building filter prompt: %w", err)
	}

	out, err := c.run(ctx, prompt, nil)
	if err != nil {
		return nil, err
	}

	var resp []struct {
		Index     int      `json:"index"`
		Relevance string   `json:"relevance"`
		Affected  []string `json:"affected"`
		Summary   string   `json:"summary"`
	}
	if err := decodeJSON(out, &resp); err != nil {
		slog.Debug("unparseable filter response", "result", out)
		return nil, fmt.Errorf("decoding filter response: %w", err)
	}

	findings := make([]Finding, 0, len(resp))
	for _, r := range resp {
		if r.Index < 0 || r.Index >= len(items) {
			slog.Warn("claude returned unknown item index", "index", r.Index)
			continue
		}
		findings = append(findings, Finding{
			Item:      items[r.Index],
			Relevance: r.Relevance,
			Affected:  r.Affected,
			Summary:   r.Summary,
		})
	}
	return findings, nil
}

func (c *ClaudeCLI) Research(ctx context.Context, f Finding, env *environment.Environment) (Finding, error) {
	prompt, err := researchPrompt(f, env)
	if err != nil {
		return f, fmt.Errorf("building research prompt: %w", err)
	}

	out, err := c.run(ctx, prompt, researchTools)
	if err != nil {
		return f, err
	}

	var resp struct {
		Research   string   `json:"research"`
		References []string `json:"references"`
	}
	if err := decodeJSON(out, &resp); err != nil {
		slog.Debug("unparseable research response", "title", f.Item.Title, "result", out)
		return f, fmt.Errorf("decoding research response: %w", err)
	}

	f.Research = resp.Research
	f.References = resp.References
	return f, nil
}

// run executes `claude -p` with the prompt on stdin and returns the text
// result from the JSON envelope. Only the given tools are made available.
func (c *ClaudeCLI) run(ctx context.Context, prompt string, tools []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	toolList := strings.Join(tools, ",")
	args := []string{
		"-p",
		"--output-format", "json",
		"--no-session-persistence",
		"--tools", toolList,
	}
	if len(tools) > 0 {
		args = append(args, "--allowedTools", toolList)
	}
	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}

	cmd := exec.CommandContext(ctx, c.Bin, args...)
	// On timeout, kill claude together with any processes it started. If one
	// escaped the group and still holds stdout open, stop waiting on it after
	// a few seconds.
	killProcessGroup(cmd)
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	slog.Debug("running claude", "bin", c.Bin, "model", c.Model, "tools", toolList,
		"prompt_bytes", len(prompt), "timeout", c.Timeout)
	start := time.Now()

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("running %s: timed out after %s", c.Bin, c.Timeout)
		}
		return "", fmt.Errorf("running %s: %w: %s", c.Bin, err, strings.TrimSpace(stderr.String()))
	}

	var envelope struct {
		IsError  bool    `json:"is_error"`
		Result   string  `json:"result"`
		CostUSD  float64 `json:"total_cost_usd"`
		NumTurns int     `json:"num_turns"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		slog.Debug("unparseable claude output", "stdout", stdout.String(), "stderr", stderr.String())
		return "", fmt.Errorf("decoding claude output: %w", err)
	}
	if envelope.IsError {
		return "", fmt.Errorf("claude returned an error: %s", envelope.Result)
	}

	slog.Debug("claude call finished", "duration", time.Since(start).Round(time.Millisecond),
		"cost_usd", envelope.CostUSD, "turns", envelope.NumTurns, "result_bytes", len(envelope.Result))
	return envelope.Result, nil
}

// decodeJSON parses the JSON value in s, tolerating surrounding prose or a
// markdown code fence.
// TODO: consider --json-schema for structured output instead.
func decodeJSON(s string, v any) error {
	start := strings.IndexAny(s, "[{")
	end := strings.LastIndexAny(s, "]}")
	if start < 0 || end < start {
		return errors.New("no JSON found in response")
	}
	return json.Unmarshal([]byte(s[start:end+1]), v)
}
