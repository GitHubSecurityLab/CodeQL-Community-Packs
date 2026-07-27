# Copilot instructions for CodeQL-Community-Packs

This repo periodically bumps its pinned CodeQL CLI version and publishes query/library packs to
GHCR. **`CONTRIBUTING.md`'s "Releases & publishing" section is the authoritative, mechanical
process** — read it first. This file is higher-level guidance for the parts that process doc can't
cover: judgment calls, failure modes, and habits that keep this work from going sideways.

## Before starting any version-bump work

- Check for an already-in-flight bump first: open PRs on `chore/update-codeql-cli-*` branches, the
  "CodeQL CLI update available" tracking issue, and recent `update-codeql-version.yml` runs. Don't
  start a second bump on top of an unfinished one.
- Confirm `.codeqlversion` and `.release.yml`'s `version:` on `main` actually match your assumptions
  before triggering anything — don't trust stale context from an earlier session or PR description.

## Judgment calls — flag to a human, don't resolve solo

- **Whether/when to take a CLI bump at all.** Detection only flags that a newer CLI exists; taking
  the upgrade (and owning whatever it breaks) is a deliberate, human-timed decision, not something
  to run unattended just because a newer version is available.
- **Whether a failure is our bug or upstream's.** Before treating a dependency/registry failure as
  something to fix in this repo, check whether it's specific to one language or affects the
  upstream library broadly (compare against the equivalent upstream package/pin for other
  languages at the same CodeQL release tag). Genuine upstream gaps (missing/unpublished packages,
  broken releases) need to wait on upstream, not a workaround here — confirm which case you're in
  with the user before proceeding either way.
- **Combining a release cut with a dependency-refresh bump** vs. keeping them as separate PRs.
  Prefer separate when breakage is plausible (most minor/major CLI bumps); only combine them when
  you're confident CI will be green without further fixes.
- **Deciding how to fix upstream API breakage.** Mechanically silencing a warning or deprecation is
  not the same as correctly migrating to the replacement API — confirm the replacement's semantics
  actually match before treating a fix as done.

## Known failure modes to design around

- **Per-language loops with no failure isolation are fragile.** Any automation that iterates over
  every language/pack directory and dies on the first hard error will silently discard all
  progress made before the failure, with no partial PR or partial commit. When you hit this, don't
  just retry — isolate which language/pack is actually broken, and prefer fixing or working around
  it (or, if you're touching the automation itself, add per-item error isolation) rather than
  re-running the whole thing hoping it clears.
- **A strict "fail on any warning" compile mode hides everything after the first failure.** Always
  do a full, non-aborting sweep across every language yourself before trusting a single CI failure
  report as the exhaustive list of what's broken — otherwise you'll fix one thing, re-push, and
  discover the next issue only on the following CI run.
- **A fully green compile/test stage does not mean CI passed overall.** Separate aggregation/
  validation jobs can still fail on result-level diffs even when every per-language job is
  individually green. Always check the overall run conclusion, not just individual job status.
- **Not every CI failure is locally reproducible.** Environment gaps (missing local tooling,
  CI-only fixture checkouts) can block a local repro even when the underlying fix is correct. When
  this happens, reconstruct the expected change directly and precisely from the CI-reported diff
  rather than skipping it or guessing at a fix.
- **Local diagnostic runs can leave incidental changes behind** (e.g. lockfile churn from a
  dependency-resolution command run just to investigate). Diff your changes before committing and
  strip out anything that isn't part of the actual fix.
- **Never hand-edit a value that an automation tool computes as a delta.** If a release-bump tool
  determines its next version by diffing against the current recorded value, editing that value
  directly removes the delta it needs and causes it to overshoot on its next run.

## Delegating to the Copilot coding agent

- Scope each delegated task to one language (or one clearly-bounded unit of work) at a time rather
  than one comprehensive multi-language ask. Coding agent sessions have a real time budget; a
  narrower scope finishes with headroom to spare and makes a timeout non-fatal, since whatever's
  already committed survives independently.
- Front-load the task with exact file/line/replacement detail when you already know it (e.g. from
  your own local investigation) rather than leaving the agent to rediscover failures one CI run at
  a time.

## PR hygiene

- **Before calling any PR done or merge-ready**, proactively fetch and review automated reviewer
  comments — don't wait to be asked. Verify each comment against real evidence (logs, actual
  tool/API behavior) rather than assuming it's correct, fix genuine issues, and reply on-thread
  explaining the fix or why none was needed.
- **Never leave a review comment thread unanswered or silently resolved.** If you notice one that
  was closed without a reply, go back and reply — even after the fact.

## Timing expectations

- Full multi-language CI runs and full publish runs are legitimately slow (tens of minutes each,
  with the slowest single language/pack job often the long pole). Don't assume a stall just
  because a run has been going for a while — check run/job status before intervening.
- Budget generously for coding agent sessions and check status periodically rather than assuming
  quick turnaround, especially for anything spanning multiple files or languages.
