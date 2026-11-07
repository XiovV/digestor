# digestor

A Go CLI that fetches security news from RSS feeds and advisory databases (GitHub Advisory Database, OSV.dev) and has Claude keep only the items that affect the user's stack (described in a YAML file). It then researches the relevant items online and sends a digest by email, Discord or Gotify. Module: `github.com/XiovV/digestor`.

## Flow
`cmd/digestor/main.go` → `app.App.Run`:
1. `App.fetch` collects items newer than `DIGESTOR_LOOKBACK` from two sources and merges them newest first:
   - `feed.Fetch` reads every `RSS_FEEDS` URL concurrently with gofeed.
   - `advisory.Client.Fetch` runs the YAML `advisories` queries concurrently (GitHub `GET /advisories`, GitHub `GET /repos/{owner}/{repo}/security-advisories`, OSV `POST /v1/query`). It drops withdrawn advisories, merges duplicates by ID/alias (github wins over github_repos, which wins over osv) and turns each advisory into a `feed.Item` whose summary lists IDs, severity and affected/patched versions.
   - Inside each source a failing feed or query is logged and skipped. If one source fails completely, the run continues with the other and exits non-zero. It stops if every configured source fails or none is configured.
2. `Analyzer.Filter` makes **one** Claude call for the whole batch, with no tools, and gets back `[]Finding` (relevance, affected components, summary).
3. `Analyzer.Research` makes one Claude call **per finding whose relevance is in `research_relevance`** (YAML, default `[critical, high]`, `[]` disables); other findings skip research, with only `WebSearch,WebFetch` allowed. If it fails, the unresearched finding is kept.
4. `digest.Digest` is rendered to Markdown and sent with `notify.SendAll`. Each notifier runs even if another fails, and errors are joined. The exit code is non-zero if any stage failed.

## Layout
```
cmd/digestor/main.go      flags (-env, -dry-run, -v), wiring
internal/config           all settings from env vars (LoadDotenv fills them from .env first); a notifier is enabled when its vars are set
internal/environment      YAML schema, validation, Describe() for prompts
internal/feed             gofeed fetching and time window
internal/advisory         GitHub Advisory Database and OSV.dev queries → feed.Item
internal/analyzer         Analyzer interface; ClaudeCLI (runs `claude -p`); prompt templates
internal/digest           Digest type, Markdown/Text rendering
internal/notify           Notifier interface; email/discord/gotify/stdout
internal/app              pipeline
environment.example.yaml  documented example of the YAML schema
.env.example              every env var
```

## Key decisions (agreed with the user, don't change without asking)
- **Claude is called by running the Claude Code CLI as a subprocess, not through the API or an SDK.** The command is `claude -p --output-format json --no-session-persistence --tools <list> [--allowedTools <list>] [--model X]`, with the prompt on stdin. `ClaudeCLI.run` reads `result` from the JSON envelope, and `decodeJSON` pulls the JSON out of the result text.
- **One-shot.** An external scheduler (cron, systemd, k8s CronJob) runs it. There is no daemon mode.
- **No dedup state.** The lookback window is the only filter. A story repeated across feeds is merged by the prompt.
- **Config.** Runtime settings and secrets come only from env vars. At startup `config.LoadDotenv` reads `.env` from the working directory, if present, and sets only variables that aren't already set, so the real environment wins. It's a small stdlib parser (comments, `export`, single/double quotes, multi-line double-quoted values). The YAML holds the prompts, the environment info and the advisory queries (`advisories`). RSS feeds stay in env (`RSS_FEEDS`, optional when the YAML has advisories). `GITHUB_TOKEN` (optional) raises the GitHub API limit from 60 to 5000 requests/hour.
- **Minimal dependencies:** only `github.com/mmcdole/gofeed` and `go.yaml.in/yaml/v3`. Use the stdlib for everything else (`net/smtp`, `net/http`, `os/exec`, `text/template`, `log/slog`).

## Environment YAML
- **Fields:** `prompt` (optional), `research_prompt` (optional), `research_relevance` (optional, subset of `critical|high|medium|low`, nil → `[critical, high]` set in `Load`), `context` (optional), `stack` (required, not empty) and `advisories` (optional).
- **Stack entries:** `name` (required), `vendor`, `type` (free-form), `version` (string), `exposure` (`internet|internal|local`), `notes`.
- **Advisories:** three lists, one per endpoint. Go adds the lookback window, paging (max 10 pages per query), headers and the token; the YAML only names what to query.
  - `github`: `name`, `ecosystem`, `affects` (package names, optional `@version`), `severity` (one value), `type`, `cwes`; at least one of ecosystem/affects/cwes. Ecosystem, severity and type are checked against GitHub's values.
  - `github_repos`: `owner/name` strings. Paging stops at the first advisory older than the window.
  - `osv`: `name`, and either `purl` or `ecosystem` + `package` (+ `version`). OSV ecosystem names aren't validated (the list grows and includes `Debian:12`-style names).
- **Unknown keys are rejected** (`KnownFields(true)`). Validation errors are joined.
- `Describe()` marshals only `context` and `stack` into the prompts.
- **Prompt override:** `prompt` replaces only `defaultPrompt` (the analyst instructions in `internal/analyzer/prompt.go`). The environment block, the items, the duplicate rule and the JSON output contract are always added by Go, so a user prompt can't break parsing. `research_prompt` works the same way: it replaces only `defaultResearchPrompt`, and the environment, the finding and the JSON output contract are added by Go.

## Status
- **Done:** config, YAML schema, feed fetching, the Claude CLI analyzer, the advisory sources (GitHub and OSV), the pipeline, the stdout notifier (`-dry-run`), and the Discord notifier (splits on lines into ≤2000-character messages, retries once on 429, disables mentions, strips the webhook URL from errors).
- **Stubbed** (return `not implemented`):
  - `notify/email.go`: should use net/smtp with STARTTLS.
  - `notify/gotify.go`: POST `/message` with the `X-Gotify-Key` header and markdown extras.
- `digest.Text()` just returns the Markdown.
- **Known issues:**
  - Research is slow: each call takes about 30–90 seconds and calls run one after another. Research is limited to `research_relevance` (critical/high by default). Other ideas: run them in parallel with a limit, use a cheaper model for the filter step, and cap the number researched.
  - Research output can be several thousand characters, too long for Discord and Gotify. The default research prompt needs a length limit (users can already set one through `research_prompt`).

## Commands
```sh
make vet test build
RSS_FEEDS="https://feeds.feedburner.com/TheHackersNews" go run ./cmd/digestor -dry-run -v -env environment.example.yaml
```
A live run makes real Claude calls, which cost money and take minutes when there are findings. Run it in the background, and don't pipe it through `tail`, because `tail` hides all output until the run ends. Unit tests don't call Claude.

## Conventions
- Each package has a short package doc comment. Errors are wrapped with `fmt.Errorf("...: %w")`, and multiple failures are joined with `errors.Join`.
- Logging uses `log/slog` and writes to stderr. The digest goes to stdout.
- Tests are table-driven and use the stdlib `testing` package only. Files are written with `t.TempDir()`.
- `environment.yaml`, `.env` and the `/digestor` binary are gitignored.
