package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/XiovV/digestor/internal/advisory"
	"github.com/XiovV/digestor/internal/analyzer"
	"github.com/XiovV/digestor/internal/app"
	"github.com/XiovV/digestor/internal/config"
	"github.com/XiovV/digestor/internal/environment"
	"github.com/XiovV/digestor/internal/notify"
)

func main() {
	envFile := flag.String("env", "", "path to the environment YAML (overrides DIGESTOR_ENV_FILE)")
	dryRun := flag.Bool("dry-run", false, "print the digest to stdout instead of sending it")
	verbose := flag.Bool("v", false, "enable debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if err := run(*envFile, *dryRun); err != nil {
		slog.Error("digestor failed", "err", err)
		os.Exit(1)
	}
}

func run(envFile string, dryRun bool) error {
	if err := config.LoadDotenv(".env"); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if envFile != "" {
		cfg.EnvFile = envFile
	}

	env, err := environment.Load(cfg.EnvFile)
	if err != nil {
		return err
	}
	slog.Debug("loaded environment", "path", cfg.EnvFile, "components", len(env.Stack),
		"advisory_queries", env.Advisories.Len(), "github_token", cfg.GitHubToken != "",
		"research_relevance", env.ResearchRelevance, "custom_prompt", env.Prompt != "",
		"custom_research_prompt", env.ResearchPrompt != "")

	notifiers := notify.FromConfig(cfg)
	if dryRun {
		notifiers = []notify.Notifier{&notify.Writer{W: os.Stdout}}
	}
	if len(notifiers) == 0 {
		slog.Warn("no notifiers configured; the digest will not be delivered")
	}

	a := &app.App{
		Config: cfg,
		Env:    env,
		Analyzer: &analyzer.ClaudeCLI{
			Bin:     cfg.Claude.Bin,
			Model:   cfg.Claude.Model,
			Timeout: cfg.Claude.Timeout,
		},
		Advisories: &advisory.Client{Token: cfg.GitHubToken},
		Notifiers:  notifiers,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return a.Run(ctx)
}
