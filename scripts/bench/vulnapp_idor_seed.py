#!/usr/bin/env python3
"""Give OWASP VulnerableApp's IDOR cases a real session before they are captured.

usage: vulnapp_idor_seed.py IN_REQUESTS_JSON OUT_REQUESTS_JSON [APP_BASE]

VulnerableApp's IDORVulnerability levels answer "Invalid token" to the placeholder cookie
(token_levelN=test) the generated request list carries, so the scanner's IDOR check sees an error
page and has nothing to swap. This logs in to each level the way the level's own page does (POST
username/password; the page pre-fills Alice and her password) and replaces the case's cookies with
the ones the login set: the signed token, and per level the client-held userId/role cookies.

This is benchmark knowledge - the app's login route, account and cookie names - so it lives here
and never in the scanner. A level whose login fails keeps its original cookies and is reported on
stderr, so the case scores as a miss rather than being silently dropped.
"""
import http.cookiejar
import json
import sys
import urllib.parse
import urllib.request

ACCOUNT = {"username": "Alice", "password": "P@ssw0rd!2026"}


def login(base, level):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                         urllib.request.ProxyHandler({}))
    url = "%s/IDORVulnerability/%s" % (base, level)
    data = urllib.parse.urlencode(ACCOUNT).encode()
    with opener.open(urllib.request.Request(url, data=data, method="POST"), timeout=30) as r:
        body = json.loads(r.read().decode() or "{}")
    if not body.get("isValid"):
        raise RuntimeError("login refused: %r" % body)
    return {c.name: c.value for c in jar}


def main():
    src, dst = sys.argv[1], sys.argv[2]
    base = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:9090/VulnerableApp"
    reqs = json.load(open(src))
    for r in reqs:
        if not r["test"].startswith("IDORVulnerability/"):
            continue
        level = r["test"].split("/")[1]
        try:
            r["cookies"] = login(base, level)
        except Exception as e:  # reported, not hidden
            print("%s: login failed, cookies left as generated: %s" % (r["test"], e), file=sys.stderr)
    json.dump(reqs, open(dst, "w"), indent=1)


if __name__ == "__main__":
    main()
