# A state file replaces the lookback window

digestor used to be stateless: each run fetched items published within `DIGESTOR_LOOKBACK` and kept no memory between runs, so a schedule that didn't match the window either repeated items or missed them. It now keeps a JSON state file with the start of the last successful run and every digested item. The fetch window runs from the last successful run minus an overlap (`DIGESTOR_OVERLAP`, 48h) to now, capped at `DIGESTOR_MAX_WINDOW` (7d), and already-digested items are dropped before Claude sees them. The overlap catches items that appear at a source after their publish date, and dedup makes that overlap free.

## Considered Options

- **Strict window from the last run, no overlap.** Rejected: items that show up at a source after their publish date (feed lag, OSV import delay) would be lost without any sign.
- **A checkpoint per feed and per advisory query.** Rejected for now: it closes the gap left by outages longer than the overlap, but its keys change when a query is edited and orphaned checkpoints need cleaning up. One checkpoint for the whole run, plus the overlap, is enough.
- **SQLite.** Rejected: it would add a dependency, and a JSON file is enough for a few thousand keys pruned to the maximum window.

## Consequences

- A run only counts once at least one notifier delivered the digest. Until then nothing is written, so the window keeps growing until the maximum window caps it.
- Updated advisories (higher severity, new affected versions) are not digested again, because the ID is already known.
- Two runs at the same time can send the same digest twice and overwrite each other's state. Stopping that is the scheduler's job.
- In ephemeral environments (a k8s CronJob without a volume), every run is a first run.
