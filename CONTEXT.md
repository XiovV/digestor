# digestor

Turns security news and advisories into a digest of only what affects the user's stack.

## Language

**Source**:
A place items come from: an RSS feed, or an advisory database query (GitHub Advisory Database, OSV.dev).
_Avoid_: Provider, origin

**Item**:
One entry from a source: a news article or an advisory.
_Avoid_: Post, entry, story

**Finding**:
Claude's verdict on one item: its relevance to the stack, the affected components and a summary. A finding with relevance `none` is not relevant.
_Avoid_: Result, match, alert

**Digest**:
The report sent after a run: the relevant findings, followed by the not-relevant items with their reasons.
_Avoid_: Report, newsletter, summary

**Fetch window**:
The range of publish dates a run asks its sources for: from the start of the last successful run minus the overlap, up to now, and never further back than the maximum window. With no successful run yet, it starts at now minus the overlap.
_Avoid_: Lookback, time window, range

**Overlap**:
How far the fetch window reaches back before the last successful run, so items that show up at a source after their publish date are still caught.
_Avoid_: Grace period, buffer, margin

**Successful run**:
A run whose digest reached at least one notifier. Only a successful run moves the fetch window forward and records its digested items.
_Avoid_: Completed run, clean run

**Digested item**:
An item that appeared in a delivered digest, as a finding or under "Not relevant". Digested items are remembered across runs and never digested again. Two items are the same if they share an advisory ID or alias, or, for news, the same feed and GUID (or link when there is no GUID).
_Avoid_: Rated item, seen item, processed item
