#!/usr/bin/env bash
# affected-go-tests.sh BASE [HEAD] — print, one per line, the burpsy-go packages whose tests a diff
# can break: every package a changed file belongs to, plus every package that imports one of those
# (transitively, test imports included). This is the T1/T2 test set in docs/DEVELOPMENT-PROCESS.md.
#
#   pkgs=$(scripts/affected-go-tests.sh origin/master) || exit 1
#   [ -n "$pkgs" ] && (cd burpsy-go && go test -count=1 -timeout 30m $pkgs)
#
# BASE...HEAD is a three-dot diff (from their merge base), so a branch that is behind master is not
# blamed for master's own changes. HEAD defaults to HEAD. The import graph is read from the CHECKED-
# OUT tree, so HEAD should be what is checked out — pass a different HEAD only to ask "which files
# changed", not to analyse another tree.
#
# Why not the whole suite: every Go failure the full suite caught on 2026-10-09 was inside "changed
# packages + reverse importers", at roughly a third of the wall time. What this set CANNOT see:
#
#   - Tests that read a file without importing it (source greps, fixtures in another package's
#     testdata, a doc a test pins). Only the explicit rules below cover those; a new read of that
#     kind is invisible until a rule is added for it.
#   - Merge skew: two branches that each pass alone and break together. Only a run on the exact
#     merged tree catches that, which is why CI (T3) runs the full suite on what lands. This script
#     narrows the inner loop; it is never the gate.
#
# Edge cases, each handled deliberately rather than by accident:
#   - no change under burpsy-go/ and no rule fires: prints nothing and exits 0 (say so on stderr);
#     an empty list is "nothing to run", not "go test ." — the module root holds no package.
#   - a deleted package: it no longer exists to be tested, so it is dropped (named on stderr). The
#     packages that imported it had to change too, so their own diff covers them.
#   - a changed file that is not a .go file (testdata, an embedded asset, the UI bundle): it is
#     attributed to the nearest enclosing directory that is a package — internal/web/ui/** lands on
#     internal/web, which go:embeds the bundle and greps the UI source.
#   - go.mod / go.sum: every package.
#   - files outside burpsy-go/: only the explicit rules below apply; everything else is ignored.
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 BASE [HEAD]" >&2
  exit 2
fi
base=$1
head=${2:-HEAD}

repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
gotree="$repo/burpsy-go"
cd "$gotree"

git rev-parse --verify --quiet "$base^{commit}" >/dev/null || { echo "$0: unknown BASE '$base'" >&2; exit 2; }
git rev-parse --verify --quiet "$head^{commit}" >/dev/null || { echo "$0: unknown HEAD '$head'" >&2; exit 2; }

mod=$(go list -m)
# Every package that exists in the checked-out tree, as a directory relative to burpsy-go/.
mapfile -t pkgdirs < <(go list -f '{{.Dir}}' ./... | sed "s#^$gotree/\{0,1\}##; s#^\$#.#")
declare -A ispkg=()
for d in "${pkgdirs[@]}"; do ispkg["$d"]=1; done

declare -A want=()
# add DIR — DIR relative to burpsy-go/; "." is the module root package.
add() { if [ "$1" = "." ]; then want["$mod"]=1; else want["$mod/$1"]=1; fi; }
# reads DIR — DIR's tests READ the changed file. Only DIR itself is affected: a package that imports
# DIR does not run DIR's tests, so reverse dependencies are not added for these.
declare -A readers=()
reads() { readers["$mod/$1"]=1; }
all=0

# Repo-root-relative paths (deleted files included: a deletion can break the package it left).
mapfile -t files < <(git -C "$repo" diff --name-only --no-renames "$base...$head")

for f in "${files[@]}"; do
  [ -n "$f" ] || continue
  case "$f" in
    burpsy-go/go.mod | burpsy-go/go.sum) all=1 ;;
    burpsy-go/*)
      rel=${f#burpsy-go/}
      dir=$(dirname "$rel")
      # Walk up to the nearest directory that is a package in this tree.
      while [ "$dir" != "." ] && [ -z "${ispkg[$dir]:-}" ]; do dir=$(dirname "$dir"); done
      if [ -n "${ispkg[$dir]:-}" ]; then
        add "$dir"
      elif [[ "$rel" == *.go ]]; then
        echo "note: $f belongs to no package in this tree (deleted package?) — skipped" >&2
      fi
      ;;
  esac

  # Explicit rules: tests that READ another directory's files rather than importing its package.
  # Each names the test that does the reading, so a rule can be deleted when its test is.
  case "$f" in
    # internal/web/scan_config_selection_test.go loads a scanner testdata config.
    burpsy-go/internal/scanner/testdata/*) reads internal/web ;;
    # internal/proxy/tls_policy_test.go greps cmd/burpsy/main.go.
    burpsy-go/cmd/burpsy/main.go) reads internal/proxy ;;
    # internal/web/pkcs11_limitation_test.go greps internal/netauth/clientcert.go.
    burpsy-go/internal/netauth/clientcert.go) reads internal/web ;;
    # cmd/burpsy/hooks_parse_test.go parses every committed .beads/hooks/* under its shebang.
    .beads/hooks/*) reads cmd/burpsy ;;
  esac
  # internal/web/ui_source_bytes_test.go (TestNoTrackedTextFileIsInvisibleToGrep) reads EVERY
  # tracked text file in the repository for NUL bytes, wherever it lives. A deleted file holds none.
  case "${f,,}" in
    *.go | *.ts | *.tsx | *.js | *.jsx | *.css | *.md | *.json | *.yml | *.yaml | *.sh | *.html | *.toml | *.txt | *.sql)
      if git -C "$repo" cat-file -e "$head:$f" 2>/dev/null; then reads internal/web; fi ;;
  esac
done

if [ "$all" = 1 ]; then
  go list ./...
  exit 0
fi

if [ ${#want[@]} -eq 0 ] && [ ${#readers[@]} -eq 0 ]; then
  echo "note: no change between $base and $head affects a burpsy-go package — nothing to test" >&2
  exit 0
fi

# Keep only packages that exist now (a deleted package has nothing left to test).
declare -A exists=()
while read -r p; do exists["$p"]=1; done < <(go list ./...)
for p in "${!want[@]}"; do
  if [ -z "${exists[$p]:-}" ]; then
    echo "note: $p no longer exists — dropped" >&2
    unset 'want[$p]'
  fi
done

# Reverse dependencies, test imports included. `go list -test` lists each package's test variants
# ("p [p.test]", "p_test [p.test]", "p.test") whose .Deps carry everything its tests pull in; a
# package is affected when any of its variants depends on (or is) a wanted package.
wanted=$(printf '%s\n' "${!want[@]}")
{
  [ ${#readers[@]} -eq 0 ] || printf '%s\n' "${!readers[@]}"
  [ -z "$wanted" ] || go list -test -f '{{.ImportPath}} {{join .Deps " "}}' ./... | awk -v c="$wanted" '
  BEGIN { n = split(c, a, "\n"); for (i = 1; i <= n; i++) if (a[i] != "") want[a[i]] = 1 }
  {
    p = $1
    sub(/\.test$/, "", p); sub(/_test$/, "", p)
    for (i = 1; i <= NF; i++) {
      d = $i; sub(/ \[.*$/, "", d)
      if (d in want) { print p; next }
    }
  }'
} | sort -u
