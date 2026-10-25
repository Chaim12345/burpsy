#!/usr/bin/env bash
# image.sh — the Buildkite bootstrap step (see pipeline.yml). Builds the burpsy agent image into the
# cluster's internal registry unless an image for exactly these inputs is already there, then
# uploads .buildkite/steps.yml with BURPSY_CI_IMAGE pointing at it.
#
# The tag is a hash of everything the image is built from (the Dockerfile, the install script it
# runs, and burpsy-go/go.mod, which sets the Go version), so a pin bump, a Dockerfile change or a
# Go bump builds a new image and every other build reuses the
# last one. Nothing leaves the cluster: no external registry, no credentials in the repository.
set -euo pipefail

: "${BUILDKITE_HOSTED_REGISTRY_URL:?runs on a Buildkite hosted agent, which sets BUILDKITE_HOSTED_REGISTRY_URL}"

tag=$(cat .buildkite/Dockerfile scripts/ci-install-tools.sh burpsy-go/go.mod | sha256sum | cut -c1-16)
image="$BUILDKITE_HOSTED_REGISTRY_URL/burpsy-ci:$tag"

# Its stderr is kept: a registry that cannot be reached looks the same as "no such image" by exit
# status, and rebuilding on every build would otherwise be invisible.
if inspect_err=$(docker manifest inspect "$image" 2>&1 >/dev/null); then
  echo "--- reusing $image"
else
  echo "--- building $image (docker manifest inspect said: ${inspect_err:-nothing})"
  docker build -f .buildkite/Dockerfile -t "$image" .
  docker push "$image"
fi

echo "--- uploading the test steps to run in $image"
BURPSY_CI_IMAGE=$image buildkite-agent pipeline upload .buildkite/steps.yml
