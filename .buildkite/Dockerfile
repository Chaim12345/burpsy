# Agent image for the `burpsy` Buildkite queue (see .buildkite/README.md). Build it from the
# repository root, since it copies the install script in:
#
#   docker build -f .buildkite/Dockerfile .
#
# It provides the toolchains and bakes in the pinned test tools. Each step still runs
# scripts/ci-install-tools.sh, which skips every tool already at its pin, so an image built before a
# pin changed still tests against the newly pinned release. Rebuild the image when the script
# changes to get that time back.
FROM golang:1.26.2-bookworm

# Buildkite hosted agents need git, ca-certificates and bash in the image (they add the agent and
# docker themselves) and run it as its own user; this image stays root. pipefail so a failed
# download in a `curl | bash` below fails the build instead of leaving a dangling symlink.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Chromium for the DOM catalog rows (the suite refuses to run without a browser), xmllint for the
# Burp-XML DTD tests, unzip/curl for ci-install-tools.sh, git for the checkout and diffs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium libxml2-utils unzip curl git ca-certificates bash \
 && rm -rf /var/lib/apt/lists/*

# bun is pinned exactly: dist/app.js is byte-reproducible only with 1.4.2.
RUN curl -fsSL https://bun.sh/install | bash -s "bun-v1.4.2" \
 && ln -s /root/.bun/bin/bun /usr/local/bin/bun

ENV PATH="/root/.local/bin:${PATH}"

# The pinned ffuf / nuclei / interactsh-client and the nuclei template corpus, hash-checked by the
# same script CI runs. The download cache is dropped: the stamps, not the archives, mark them done.
COPY scripts/ci-install-tools.sh /usr/local/share/burpsy/ci-install-tools.sh
RUN /usr/local/share/burpsy/ci-install-tools.sh \
 && rm -rf /root/.cache/burpsy-ci-downloads
