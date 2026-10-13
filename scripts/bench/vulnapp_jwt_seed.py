#!/usr/bin/env python3
"""Give OWASP VulnerableApp's JWT cases a real token, carried where the level reads it.

usage: vulnapp_jwt_seed.py IN_REQUESTS_JSON OUT_REQUESTS_JSON [APP_BASE]

The generated request list sends every JWTVulnerability level `?fetch=true` (LEVEL_1 a jwt.io sample
token). With `fetch=true` a level ISSUES a token and ignores any it was sent, so the captured request
carries no token the scanner could forge from, and every JWT check returns "nothing to do". The
request a level actually verifies is the one WITHOUT `fetch`, carrying the token it issued:

  LEVEL_1            ?JWT=<token>                 (queryParams.get(JWT))
  LEVEL_7            Authorization: <token>       (raw, no "Bearer"; the level reads the header as is)
  every other level  Cookie: JWT=<token>          (the "cookie" header, split on "=")

This fetches each level's own token (GET LEVEL_N?fetch=true answers {"content": <token>}; LEVEL_8,
9 and 13 issue RS256 / embedded-JWK tokens, so a token from another level would be the wrong
algorithm) and rewrites the case into that verification request. The tokens carry no exp claim, so
they do not go stale during a run.

Every JWT case also gets the family's token-issuing pages as companions sent before it
(add_issuer_companions): the history a crawl of the family would have captured.

This is benchmark knowledge - the app's level routes and where each reads its token - so it lives
here and never in the scanner. A level whose token cannot be fetched keeps its generated request and
is reported on stderr, so the case scores as a miss rather than being silently dropped.
"""
import json
import sys
import urllib.request

FAMILY = "JWTVulnerability/"
QUERY_LEVELS = {"LEVEL_1"}
HEADER_LEVELS = {"LEVEL_7"}

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def fetch_token(base, level):
    url = "%s/JWTVulnerability/%s?fetch=true" % (base, level)
    with _opener.open(url, timeout=30) as r:
        body = json.loads(r.read().decode() or "{}")
    tok = body.get("content") or ""
    if tok.count(".") != 2:
        raise RuntimeError("no JWT in the level's answer: %r" % (body,))
    return tok


def seed_entry(r, base):
    """Rewrite one JWT case in place into the level's verification request. Raises on failure."""
    level = r["test"].split("/")[1]
    tok = fetch_token(base, level)
    q = dict(r.get("query") or {})
    q.pop("fetch", None)
    q.pop("JWT", None)
    cookies = dict(r.get("cookies") or {})
    headers = dict(r.get("headers") or {})
    if level in QUERY_LEVELS:
        q["JWT"] = tok
    elif level in HEADER_LEVELS:
        headers["Authorization"] = tok
    else:
        cookies["JWT"] = tok
    r["query"], r["cookies"], r["headers"] = q, cookies, headers
    return r


def add_issuer_companions(entries):
    """Give every JWT case the family's token-issuing pages as companions sent BEFORE it.

    A tester's project history holds the application's other pages, not just the request under test;
    a scan that starts from one captured request has none of it. The issuing pages are what a crawl
    of this family captures (each level's `?fetch=true` answers the token it issues), so sending them
    first gives the scanner the same history a crawled project would have. Nothing names a level the
    scanner should use: every case gets every issuing page of the family, in level order. Some of
    those tokens carry a jwk header (LEVEL_9, LEVEL_13), which is how a target discloses the public key
    an algorithm-confusion check needs; the scanner finds it there generally (jwt_confusion.go).
    """
    levels = sorted({e["test"].split("/")[1] for e in entries if e["test"].startswith(FAMILY)},
                    key=lambda lv: int(lv.split("_")[1]) if lv.split("_")[1].isdigit() else 0)
    for r in entries:
        if not r["test"].startswith(FAMILY):
            continue
        root = r["url"].rsplit("/", 1)[0]
        r["companions"] = [{"test": "%s#issuer-%s" % (r["test"], lv), "method": "GET", "url": "%s/%s" % (root, lv),
                            "query": {"fetch": "true"}, "form": {}, "headers": {}, "cookies": {}, "body": None}
                           for lv in levels]
    return entries


def main():
    src, dst = sys.argv[1], sys.argv[2]
    base = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:9090/VulnerableApp"
    reqs = json.load(open(src))
    n = 0
    for r in reqs:
        if not r["test"].startswith(FAMILY):
            continue
        try:
            seed_entry(r, base)
            n += 1
        except Exception as e:  # reported, not hidden
            print("%s: token fetch failed, request left as generated: %s" % (r["test"], e), file=sys.stderr)
    add_issuer_companions(reqs)
    json.dump(reqs, open(dst, "w"), indent=1)
    print("seeded %d JWT case(s)" % n, file=sys.stderr)


if __name__ == "__main__":
    main()
