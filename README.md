# digestor

Fetches security news from RSS feeds, has Claude keep only what affects your stack, researches the relevant items online and sends you a digest.

## Requirements

- Go 1.26+
- Claude Code CLI installed and logged in (`claude` on your `PATH`)

## Install

```sh
go build -o digestor ./cmd/digestor
```

## Configure

**1. Describe your environment.** Copy the example and edit it:

```sh
cp environment.example.yaml environment.yaml
```

```yaml
prompt: |            # optional, replaces the built-in analyst instructions
  Only nginx is internet-facing, so be strict about anything else.
context: |           # optional, free text about the environment
  Small homelab: 3 Debian hosts running Docker.
stack:               # required
  - name: nginx      # required
    vendor: F5
    type: service
    version: "1.24"
    exposure: internet   # internet | internal | local
    notes: Reverse proxy for everything
```

**2. Set environment variables.** See [`.env.example`](.env.example) for the full list. digestor reads a `.env` file from the working directory if there is one (`cp .env.example .env`). Variables already set in the environment take precedence over the file.

| Variable | Default | Description |
|---|---|---|
| `RSS_FEEDS` | (required) | Feed URLs, separated by commas or newlines |
| `DIGESTOR_ENV_FILE` | `environment.yaml` | Path to the environment YAML |
| `DIGESTOR_LOOKBACK` | `24h` | Only items published within this window |
| `CLAUDE_MODEL` | CLI default | Model passed to `claude --model` |
| `CLAUDE_TIMEOUT` | `10m` | Timeout per Claude call |
| `SMTP_*` | | Email: enabled when `SMTP_HOST` is set |
| `DISCORD_WEBHOOK_URL` | | Discord: enabled when set |
| `GOTIFY_URL`, `GOTIFY_TOKEN` | | Gotify: enabled when `GOTIFY_URL` is set |

> Email and Gotify delivery are not implemented yet.

## Run

```sh
export RSS_FEEDS="https://feeds.feedburner.com/TheHackersNews,https://www.bleepingcomputer.com/feed/"
./digestor -dry-run
```

| Flag | Description |
|---|---|
| `-env <path>` | Environment YAML, overrides `DIGESTOR_ENV_FILE` |
| `-dry-run` | Print the digest to stdout instead of sending it |
| `-v` | Debug logging |

digestor runs once and exits, with a non-zero exit code if anything failed. To get a daily digest, schedule it, for example with cron:

```cron
0 7 * * * cd /opt/digestor && ./digestor
```
