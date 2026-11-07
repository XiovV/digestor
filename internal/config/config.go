// Package config loads runtime configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	EnvFile string

	// StateFile remembers the last successful run and the digested items.
	StateFile string
	// Overlap is how far the fetch window reaches back before the last
	// successful run; MaxWindow caps how far back it reaches at all.
	Overlap   time.Duration
	MaxWindow time.Duration

	// GitHubToken raises the GitHub API rate limit; optional.
	GitHubToken string

	Claude  Claude
	SMTP    SMTP
	Discord Discord
	Gotify  Gotify
}

type Claude struct {
	Bin     string
	Model   string
	Timeout time.Duration
}

type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
}

func (s SMTP) Enabled() bool { return s.Host != "" }

type Discord struct {
	WebhookURL string
}

func (d Discord) Enabled() bool { return d.WebhookURL != "" }

type Gotify struct {
	URL      string
	Token    string
	Priority int
}

func (g Gotify) Enabled() bool { return g.URL != "" }

// Load reads the configuration from the environment and validates it.
func Load() (*Config, error) {
	var errs []error

	cfg := &Config{
		EnvFile:     getenv("DIGESTOR_ENV_FILE", "environment.yaml"),
		StateFile:   getenv("DIGESTOR_STATE", "digestor-state.json"),
		GitHubToken: os.Getenv("GITHUB_TOKEN"),
		Claude: Claude{
			Bin:   getenv("CLAUDE_BIN", "claude"),
			Model: os.Getenv("CLAUDE_MODEL"),
		},
		SMTP: SMTP{
			Host:     os.Getenv("SMTP_HOST"),
			Username: os.Getenv("SMTP_USERNAME"),
			Password: os.Getenv("SMTP_PASSWORD"),
			From:     os.Getenv("SMTP_FROM"),
			To:       ParseList(os.Getenv("SMTP_TO")),
		},
		Discord: Discord{
			WebhookURL: os.Getenv("DISCORD_WEBHOOK_URL"),
		},
		Gotify: Gotify{
			URL:   os.Getenv("GOTIFY_URL"),
			Token: os.Getenv("GOTIFY_TOKEN"),
		},
	}

	var err error
	if cfg.Overlap, err = durationEnv("DIGESTOR_OVERLAP", 48*time.Hour); err != nil {
		errs = append(errs, err)
	}
	if cfg.MaxWindow, err = durationEnv("DIGESTOR_MAX_WINDOW", 7*24*time.Hour); err != nil {
		errs = append(errs, err)
	}
	if cfg.Claude.Timeout, err = durationEnv("CLAUDE_TIMEOUT", 10*time.Minute); err != nil {
		errs = append(errs, err)
	}
	if cfg.SMTP.Port, err = intEnv("SMTP_PORT", 587); err != nil {
		errs = append(errs, err)
	}
	if cfg.Gotify.Priority, err = intEnv("GOTIFY_PRIORITY", 5); err != nil {
		errs = append(errs, err)
	}

	switch {
	case cfg.Overlap <= 0 || cfg.MaxWindow <= 0:
		errs = append(errs, errors.New("DIGESTOR_OVERLAP and DIGESTOR_MAX_WINDOW must be positive"))
	case cfg.Overlap > cfg.MaxWindow:
		errs = append(errs, fmt.Errorf("DIGESTOR_OVERLAP (%s) must not be longer than DIGESTOR_MAX_WINDOW (%s)", cfg.Overlap, cfg.MaxWindow))
	}
	if cfg.SMTP.Enabled() && (cfg.SMTP.From == "" || len(cfg.SMTP.To) == 0) {
		errs = append(errs, errors.New("SMTP_FROM and SMTP_TO are required when SMTP_HOST is set"))
	}
	if cfg.Gotify.Enabled() && cfg.Gotify.Token == "" {
		errs = append(errs, errors.New("GOTIFY_TOKEN is required when GOTIFY_URL is set"))
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ParseList splits a comma- or newline-separated list, trimming blanks.
func ParseList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})

	var out []string
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func durationEnv(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func intEnv(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}
