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
feeds:               # RSS/Atom/JSON feed URLs
  - https://feeds.feedburner.com/TheHackersNews
  - https://www.bleepingcomputer.com/feed/
```

Set `feeds`, `advisories` (GitHub Advisory Database and OSV.dev queries) or both. [`environment.example.yaml`](environment.example.yaml) documents every field.

**2. Set environment variables.** See [`.env.example`](.env.example) for the full list. digestor reads a `.env` file from the working directory if there is one (`cp .env.example .env`). Variables already set in the environment take precedence over the file.

| Variable | Default | Description |
|---|---|---|
| `DIGESTOR_ENV_FILE` | `environment.yaml` | Path to the environment YAML |
| `DIGESTOR_STATE` | `digestor-state.json` | State file: the last successful run and the digested items |
| `DIGESTOR_OVERLAP` | `48h` | How far before the last successful run each fetch starts |
| `DIGESTOR_MAX_WINDOW` | `168h` | The furthest back a run fetches |
| `CLAUDE_MODEL` | CLI default | Model passed to `claude --model` |
| `CLAUDE_TIMEOUT` | `10m` | Timeout per Claude call |
| `SMTP_*` | | Email: enabled when `SMTP_HOST` is set |
| `DISCORD_WEBHOOK_URL` | | Discord: enabled when set |
| `GOTIFY_URL`, `GOTIFY_TOKEN` | | Gotify: enabled when `GOTIFY_URL` is set |

> Email and Gotify delivery are not implemented yet.

## Prompts

digestor makes two kinds of Claude calls, and each has a built-in prompt you can replace in `environment.yaml`:

- **Filter** (`prompt`): one call that rates every fetched item against your stack.
- **Research** (`research_prompt`): one call with web search per finding whose relevance is in `research_relevance` (default `[critical, high]`).

Your text replaces only the instructions below. digestor always adds your `context` and `stack`, the items (or the finding being researched) and the JSON format it expects after it, so a custom prompt can't break parsing. The filter step also asks Claude to give a short reason for every item it skips. Those items are listed under "Not relevant" at the end of the digest.

Built-in `prompt`:

```text
You are a security analyst responsible for the environment described below. You receive a batch of security news items and decide which ones I need to know about.

Rate each relevant item:
- critical: patch or mitigate today.
- high: patch or mitigate this week.
- medium: handle in the next patch window.
- low: worth knowing, no action needed.

Internet-facing components and vulnerabilities that are actively exploited raise the priority. Skip generic news, opinion pieces and anything that does not affect a component in my stack. If an item names affected versions and my version is outside that range, lower its rating or skip it.
```

Built-in `research_prompt`:

```text
You are a security analyst. The news item below was flagged as relevant to my environment.

Research it online: affected versions, CVE identifiers, whether it is actively exploited, and remediation steps. Focus on what applies to my environment.
```

The built-in research prompt doesn't limit the answer's length, and the result can run to several thousand characters, which is too long for one Discord message. If you send to Discord, consider setting your own `research_prompt` with a limit such as "Keep the answer under 800 characters".

These are copied from [`internal/analyzer/prompt.go`](internal/analyzer/prompt.go). If the two differ, the code is the current version.

## Run

```sh
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

### State

digestor remembers what it already sent in `DIGESTOR_STATE`, so you can schedule it as often as you like without getting the same item twice:

- Each run fetches items published since the last successful run minus `DIGESTOR_OVERLAP`. The overlap catches items that show up in a feed after their publish date. Items that were already digested are dropped before Claude sees them.
- A run is successful once at least one notifier delivered the digest. Only then is the state written. If delivery keeps failing, the next run fetches the same window again, but never further back than `DIGESTOR_MAX_WINDOW`.
- The first run, or a run with the state file missing, fetches `DIGESTOR_OVERLAP` alone. Set it higher for one run to get a backfill.
- `-dry-run` reads the state but never writes it, so it shows what the next real run would send.

Keep the state file on persistent storage. In a Kubernetes CronJob, mount a volume and point `DIGESTOR_STATE` at it, or every run starts over. Don't start a run while another is still going (`concurrencyPolicy: Forbid`, `flock -n` with cron), or both send the same digest.
