# Crawler coverage benchmark (burpsy-react-ui-dvi7)

`bench.py` crawls one target with burpsy and with Katana — same seed, depth and wall-clock budget,
each at its strongest settings — and reports which normalised URLs (path + query-parameter names on
the target origin) each reached: found by both, Katana only, burpsy only, split by class
(api / page / script / static).

```sh
go build -o /tmp/burpsy-bench ./cmd/burpsy
python3 scripts/crawl-benchmark/bench.py http://127.0.0.1:13000/ juice-shop \
    --depth 3 --duration 120 --burpsy /tmp/burpsy-bench --out /tmp/bench-out
```

Run it only against targets you are authorised to crawl — a local training container is the intended
use (e.g. `docker run --rm -p 127.0.0.1:13000:3000 bkimminich/juice-shop`).

## First run (2026-10-05, OWASP Juice Shop, depth 3, 120 s)

| class | both | Katana only | burpsy only |
|---|---:|---:|---:|
| api | 1 | 7 | 40 |
| page/other | 1 | 25 | 109 |
| script | 3 | 79 | 0 |
| static | 0 | 19 | 0 |
| **total** | 5 | 130 | 149 |

Raw counts overstate both sides; read the lists. What they showed:

- **Katana-only, genuine:** requests the page issues at run time (XHR/fetch observed by its headless
  browser), a `.well-known/` known file, and an i18n JSON the app loads dynamically. burpsy has no
  pass that records what a rendered page requests — the main gap class.
- **burpsy-only, genuine:** REST resource collections and app routes read out of the bundles by the
  jsluice + miner union (jwy5) that Katana's run did not reach.
- **Both sides, junk:** a large share of each side's "only" list is JavaScript fragments mis-read as
  paths (regex literals, code expressions, template placeholders). For burpsy these spend request
  budget; the normaliser should refuse code-shaped candidates.

Each class is filed as its own bead rather than fixed here.

## After 8lpc (code-shaped candidates refused)

Same target and settings: burpsy-only page/other 109 -> 81, api unchanged at 40. All 28 dropped
candidates were code (regex literals, statements, expressions, template fragments); none was a route,
and nothing new appeared — 28 fewer wasted requests per crawl of this app.
