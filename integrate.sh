#!/usr/bin/env bash
# Merge one agent branch and hold it to the same bar the branch was built against.
#
#   ./integrate.sh <branch> [<branch> ...]
#   ./integrate.sh --list
#
# Merges are sequential and each is verified before the next starts, so when something breaks it is
# unambiguous which branch broke it. A failed merge is left in place for inspection rather than
# auto-reverted — the diff is the evidence, and throwing it away to get a green tree is how a real
# regression becomes a mystery. `--abort` undoes the last one deliberately.
set -uo pipefail
cd "$(dirname "$0")"

if [ "${1:-}" = "--list" ]; then
  echo "branches not yet merged into $(git branch --show-current):"
  git branch --no-merged | sed 's/^/  /'
  exit 0
fi

if [ "${1:-}" = "--abort" ]; then
  echo "resetting to the previous commit (discarding the last merge)"
  git reset --hard HEAD~1
  exit 0
fi

[ $# -gt 0 ] || { echo "usage: $0 <branch>... | --list | --abort"; exit 2; }

BASE=$(git rev-parse --abbrev-ref HEAD)
for BR in "$@"; do
  printf '\n\033[1m################ merging %s ################\033[0m\n' "$BR"

  if ! git rev-parse --verify "$BR" >/dev/null 2>&1; then
    echo "  no such branch: $BR"; exit 1
  fi

  # Show what is coming before taking it, so an agent that strayed outside its file ownership is
  # visible at merge time rather than after the tree is already broken.
  echo "  files this branch touches:"
  git diff --stat "$BASE...$BR" | sed 's/^/    /'

  if ! git merge --no-ff --no-edit "$BR"; then
    printf '\n  \033[31mCONFLICT\033[0m — two agents touched the same file.\n'
    git diff --name-only --diff-filter=U | sed 's/^/    /'
    echo "  resolve, then: git add -A && git commit"
    exit 1
  fi

  if ./verify.sh; then
    printf '\033[32m  %s merged and verified\033[0m\n' "$BR"
  else
    printf '\n\033[31m  %s merged but FAILS verification — left in place for inspection.\033[0m\n' "$BR"
    echo "  inspect:  git show --stat HEAD"
    echo "  undo:     ./integrate.sh --abort"
    exit 1
  fi
done

printf '\n\033[1mall requested branches integrated\033[0m\n'
git log --oneline | head -10
