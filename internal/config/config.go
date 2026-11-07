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
	Feeds    []string
	EnvFile  string
	Lookback time.Duration

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
		Feeds:   ParseList(os.Getenv("RSS_FEEDS")),
		EnvFile: getenv("DIGESTOR_ENV_FILE", "environment.yaml"),
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
	if cfg.Lookback, err = durationEnv("DIGESTOR_LOOKBACK", 24*time.Hour); err != nil {
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

	if len(cfg.Feeds) == 0 {
		errs = append(errs, errors.New("RSS_FEEDS is required"))
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
