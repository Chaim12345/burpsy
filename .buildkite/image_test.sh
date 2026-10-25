#!/usr/bin/env bash
# image_test.sh — tests for .buildkite/image.sh and the Chrome warm-up timeout (bead
# burpsy-react-ui-021u). Stubs docker and buildkite-agent; needs no Docker or Buildkite.
# Run from anywhere: .buildkite/image_test.sh
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: want [$2], got [$3]"; fail=1; fi; }

mkdir "$tmp/bin"
cat >"$tmp/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >>"$STUB_LOG"
case "$1 $2" in
  "manifest inspect") echo "${STUB_MANIFEST_ERR:-no such manifest}" >&2; exit "${STUB_MANIFEST_RC:-1}" ;;
esac
exit 0
STUB
cat >"$tmp/bin/buildkite-agent" <<'STUB'
#!/usr/bin/env bash
echo "agent $*" >>"$STUB_LOG"
STUB
chmod +x "$tmp/bin/"*

run_image() { # runs image.sh in a scratch copy of the inputs so go.mod can be varied
  local w=$1; shift
  : >"$tmp/log"
  ( cd "$w" && PATH="$tmp/bin:$PATH" STUB_LOG="$tmp/log" BUILDKITE_HOSTED_REGISTRY_URL=reg.test \
      "$@" bash .buildkite/image.sh ) >"$tmp/out" 2>&1
}
mkw() {
  local w=$tmp/$1; mkdir -p "$w/.buildkite" "$w/scripts" "$w/burpsy-go"
  cp "$root/.buildkite/"{image.sh,Dockerfile,steps.yml} "$w/.buildkite/"
  cp "$root/scripts/ci-install-tools.sh" "$w/scripts/"
  cp "$root/burpsy-go/go.mod" "$w/burpsy-go/"
  echo "$w"
}
tag_of() { grep -o 'burpsy-ci:[0-9a-f]*' "$tmp/log" | head -1; }

# 1. A failed `docker manifest inspect` says why (its stderr reaches the build log).
w=$(mkw a)
run_image "$w" env STUB_MANIFEST_ERR="denied: registry unreachable"
check "manifest inspect failure is explained" 1 "$(grep -c 'registry unreachable' "$tmp/out")"
tag_a=$(tag_of)

# 2. A reused image is reported as reused and not rebuilt.
run_image "$w" env STUB_MANIFEST_RC=0
check "existing image is reused" 0 "$(grep -c 'docker build' "$tmp/log")"

# 3. A go.mod change gives a new image tag.
w2=$(mkw b)
sed -i 's/^go 1\.[0-9.]*/go 1.99.9/' "$w2/burpsy-go/go.mod"
run_image "$w2" env STUB_MANIFEST_RC=1
tag_b=$(tag_of)
if [ -n "$tag_a" ] && [ "$tag_a" != "$tag_b" ]; then echo "ok   go.mod is part of the image tag"; else echo "FAIL go.mod is part of the image tag ($tag_a vs $tag_b)"; fail=1; fi

# 4. The Chrome warm-up cannot hold a step past a TERM-ignoring Chrome.
check "warm-up timeout escalates to KILL" 1 "$(grep -c 'timeout -k 10 120' "$root/scripts/ci-install-tools.sh")"
exit $fail
