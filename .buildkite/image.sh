#!/usr/bin/env bash
# image.sh — the Buildkite bootstrap step (see pipeline.yml). Builds the burpsy agent image into the
# cluster's internal registry unless an image for exactly these inputs is already there, then
# uploads .buildkite/steps.yml with BURPSY_CI_IMAGE pointing at it.
#
# The tag is a hash of everything the image is built from (the Dockerfile and the install script it
# runs), so a pin bump or a Dockerfile change builds a new image and every other build reuses the
# last one. Nothing leaves the cluster: no external registry, no credentials in the repository.
set -euo pipefail

: "${BUILDKITE_HOSTED_REGISTRY_URL:?runs on a Buildkite hosted agent, which sets BUILDKITE_HOSTED_REGISTRY_URL}"

tag=$(cat .buildkite/Dockerfile scripts/ci-install-tools.sh | sha256sum | cut -c1-16)
image="$BUILDKITE_HOSTED_REGISTRY_URL/burpsy-ci:$tag"

if docker manifest inspect "$image" >/dev/null 2>&1; then
  echo "--- reusing $image"
else
  echo "--- building $image"
  docker build -f .buildkite/Dockerfile -t "$image" .
  docker push "$image"
fi

echo "--- uploading the test steps to run in $image"
BURPSY_CI_IMAGE=$image buildkite-agent pipeline upload .buildkite/steps.yml
