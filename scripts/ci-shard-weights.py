#!/usr/bin/env python3
"""Turn a `go test -json` run of internal/scanner into scripts/ci-shard-weights.txt.

    (cd burpsy-go && go test -count=1 -json -timeout 40m ./internal/scanner/) \\
        | scripts/ci-shard-weights.py > scripts/ci-shard-weights.txt

ci-shard.sh deals the scanner tests to three shards longest-first on these seconds. Only top-level
tests count (subtests run inside their parent). The `default` line is the median (at least 0.5s), the weight a test
not in the file gets; a stale file costs balance, never coverage.
"""
import json
import statistics
import sys

times = {}
for line in sys.stdin:
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    test = ev.get("Test", "")
    if test and "/" not in test and ev.get("Action") in ("pass", "fail", "skip"):
        times[test] = ev.get("Elapsed", 0.0)
if not times:
    sys.exit("ci-shard-weights: no test results on stdin")

print("# seconds test - per top-level internal/scanner test, from one `go test -json` run.")
print("# Regenerate: see scripts/ci-shard-weights.py. Read by scripts/ci-shard.sh (scanner balance).")
print("default %.2f" % max(0.5, statistics.median(times.values())))
for test, secs in sorted(times.items(), key=lambda kv: (-kv[1], kv[0])):
    print("%.2f %s" % (secs, test))
