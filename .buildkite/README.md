# Buildkite (optional, alongside GitHub Actions)

The required gate is GitHub Actions (`.github/workflows/go.yml`); branch protection names its
checks. This pipeline runs the same shards (`scripts/ci-shard.sh`) on Buildkite so its speed can be
compared before anything else is decided. It is **not** a required check.

## One-time setup (Buildkite organisation owner)

1. **Revoke any agent token that has been shared in chat or committed anywhere**, and create a new
   one. Agent tokens (`bkct_…`) let a machine join the cluster and receive jobs; treat them as
   secrets. Never put one in this repository.
2. Create a cluster queue named `burpsy`. For Buildkite hosted agents, use a Linux queue with a
   custom agent image built from `.buildkite/Dockerfile`; for self-hosted agents, run them on a
   machine with the same toolchains (Go from `burpsy-go/go.mod`, Chromium, bun 1.4.2, xmllint,
   curl, unzip).
3. Create a pipeline for `Chaim12345/burpsy` whose steps upload this file:
   `buildkite-agent pipeline upload .buildkite/pipeline.yml`.
4. In the pipeline's GitHub settings, build pull requests and the `master` branch. Leave it out of
   branch protection.

## What runs

| Step | Same as Actions |
|---|---|
| `lint` | `lint` job: gofmt, build, vet |
| `test` × 7 shards | `test` matrix: `scanner-budget`, `scanner-detect`, `scanner-rest`, `web`, `rest`, `race-web-0`, `race-web-1` |
| `ui` | `ui` job: `bun run check`, build, bundle freshness |

The `beads` and `review-gate` checks stay on GitHub only: they depend on GitHub's merge commit,
PR API and commit statuses.
