# Buildkite (optional, alongside GitHub Actions)

The required gate is GitHub Actions (`.github/workflows/go.yml`); branch protection names its
checks. This pipeline runs the same shards (`scripts/ci-shard.sh`) on **Buildkite hosted agents** so
its speed can be compared before anything else is decided. It is **not** a required check.

## How it runs

1. The pipeline's settings upload `.buildkite/pipeline.yml`: one bootstrap step, `.buildkite/image.sh`,
   on the hosted queue's default image (which has docker).
2. `image.sh` tags the burpsy agent image with a hash of `.buildkite/Dockerfile` and
   `scripts/ci-install-tools.sh`. If the cluster's internal registry (`$BUILDKITE_HOSTED_REGISTRY_URL`)
   has no image with that tag, it builds the Dockerfile (from the repository root) and pushes it.
   Otherwise it reuses it. A pin bump or Dockerfile change builds a new image; everything else
   reuses the last one.
3. It uploads `.buildkite/steps.yml` with `BURPSY_CI_IMAGE` set to that image. Every step then
   runs in it (`image:` at the root of `steps.yml`).

No external registry, no credentials in this repository.

## One-time setup (Buildkite organisation owner)

1. **Revoke any agent token that has been shared in chat or committed anywhere.** Hosted agents do
   not need one at all.
2. In the cluster, create a **hosted Linux** queue named `burpsy` (amd64; a 4-vCPU shape is
   comparable to a GitHub runner).
3. Create a pipeline for `Chaim12345/burpsy` whose steps are:
   `buildkite-agent pipeline upload .buildkite/pipeline.yml`. Build pull requests and the `master`
   branch. Leave it out of branch protection.

These steps can be done through the REST API with an API access token that has `read_organizations`,
`read_clusters`, `write_clusters`, `read_pipelines`, `write_pipelines` and `read_builds`. Give that
token to an agent session as an environment secret (`BUILDKITE_API_TOKEN`), never in chat.

## What runs

| Step | Same as Actions |
|---|---|
| `agent image` | (Buildkite only) build or reuse the image |
| `lint` | `lint` job: gofmt, build, vet |
| `test` × 7 shards | `test` matrix: `scanner-budget`, `scanner-detect`, `scanner-rest-0`, `scanner-rest-1`, `rest`, `race-web-0`, `race-web-1` (always the full suite; affected mode is GitHub PRs only) |
| `ui` | `ui` job: `bun run check`, build, bundle freshness |

The `beads` and `review-gate` checks stay on GitHub only: they depend on GitHub's merge commit,
PR API and commit statuses.

## Not yet verified

This has not run on Buildkite yet. Two assumptions are untested:

- the hosted agent can push to and pull from `$BUILDKITE_HOSTED_REGISTRY_URL` without extra login;
- jobs in the custom image run with `HOME=/root`, where the image keeps the baked-in tools.

If either is false, the first build will say so. `ci-install-tools.sh` still installs whatever is
missing, so the second only costs time.

## Known gaps

The image's own inputs are not pinned by digest: the `golang:1.26.2-bookworm` base image (a tag),
the `bun.sh` install script (it installs exactly bun 1.4.2, but the script itself is fetched live),
and Debian's `chromium` package. The test tools are pinned and hash-checked by
`scripts/ci-install-tools.sh`. Pin these too before relying on Buildkite for more than comparison.
