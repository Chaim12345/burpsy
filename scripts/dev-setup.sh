#!/usr/bin/env bash
# dev-setup.sh — one-time, per-clone setup the repository cannot carry in its own files.
#
# Idempotent; run it again whenever. It changes only this clone's git config (shared by all of its
# worktrees) and prints what it did and what it could not check. See docs/DEVELOPMENT-PROCESS.md.
set -euo pipefail

repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
want_bun=1.4.2
problems=0

# 1. The `ours` merge driver that .gitattributes names for the generated UI bundle. git ships no
#    built-in driver of that name; without this a merge of two rebuilt bundles falls back to a
#    text merge and stops on conflict markers (loud, but needless: the lead rebuilds anyway).
git -C "$repo" config merge.ours.name "keep our side; the file is regenerated (scripts/dev-setup.sh)"
git -C "$repo" config merge.ours.driver true
echo "ok: merge.ours.driver registered for $repo"

# 2. bun: the bundle is byte-reproducible only with the version CI pins (.github/workflows/go.yml,
#    job `ui`). A different bun produces a different dist/app.js, and CI's freshness check fails it.
if command -v bun >/dev/null 2>&1; then
  have_bun=$(bun --version)
  if [ "$have_bun" = "$want_bun" ]; then
    echo "ok: bun $have_bun"
  else
    echo "WARNING: bun $have_bun, but CI builds the bundle with bun $want_bun; a bundle built here"
    echo "         will not match CI's and the ui job will fail. Install it with:"
    echo "         curl -fsSL https://bun.sh/install | bash -s bun-v$want_bun"
    problems=$((problems + 1))
  fi
else
  echo "WARNING: bun is not installed; UI checks (bun run check) and bundle rebuilds cannot run here."
  echo "         Install bun $want_bun: curl -fsSL https://bun.sh/install | bash -s bun-v$want_bun"
  problems=$((problems + 1))
fi

# 3. Go: the version comes from burpsy-go/go.mod (CI reads the same file). Asked from inside the
#    module, so the answer is the toolchain go would actually use there (GOTOOLCHAIN may switch).
want_go=$(sed -n 's/^go //p' "$repo/burpsy-go/go.mod")
if command -v go >/dev/null 2>&1; then
  echo "ok: $(cd "$repo/burpsy-go" && go version) (go.mod asks for go $want_go)"
else
  echo "WARNING: go is not installed; burpsy-go/go.mod asks for go $want_go."
  problems=$((problems + 1))
fi

if [ "$problems" -gt 0 ]; then
  echo "dev-setup: done, with $problems warning(s) above."
else
  echo "dev-setup: done."
fi
