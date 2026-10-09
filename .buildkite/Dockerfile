# Agent image for the `burpsy` Buildkite queue (see .buildkite/README.md). It provides the
# toolchains; scripts/ci-install-tools.sh fetches and hash-checks the pinned test tools at run time.
FROM golang:1.26.2-bookworm

# Chromium for the DOM catalog rows (the suite refuses to run without a browser), xmllint for the
# Burp-XML DTD tests, unzip/curl for ci-install-tools.sh, git for the checkout and diffs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium libxml2-utils unzip curl git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# bun is pinned exactly: dist/app.js is byte-reproducible only with 1.4.2.
RUN curl -fsSL https://bun.sh/install | bash -s "bun-v1.4.2" \
 && ln -s /root/.bun/bin/bun /usr/local/bin/bun

ENV PATH="/root/.local/bin:${PATH}"
