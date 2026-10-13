#!/usr/bin/env python3
"""Give OWASP VulnerableApp's InsecureDeserialization and LDAP login cases the state a tester holds.

usage: vulnapp_state_seed.py IN_REQUESTS_JSON OUT_REQUESTS_JSON [APP_BASE]

InsecureDeserialization: the generated request list carries the placeholder cookie value "test"
(preferences_level1=test, session_level2=test, ...). The application never issues that: each level's
page first POSTs to the same level URL (save preferences, start a session, visit a section), which
sets the real cookie - base64 JSON such as {"username":"Adam","role":"USER",...}. A tester's captured
traffic carries that cookie, and only with it can a scanner see what the cookie holds. This makes
the same POST the page makes and puts the issued cookie in the case.

LDAPInjectionVulnerability: the login-shaped levels (those sending a password) are seeded with
admin/password, an account the directory does not have, so every captured login fails whatever the
filter does. LEVEL_5 answers only success or failure, so without a working login there is no
observable difference to measure. This uses the account the application's own LEVEL_5 challenge
card hands the tester (alice / alicePass123, messages.properties LDAP_*_LEVEL5_*), as a tester's own
test account would be used; the secure LEVEL_6 gets the same account, so it is tested under the
same conditions.

This is benchmark knowledge - the app's routes, form fields, cookie names and account - so it lives
here and never in the scanner. A level whose cookie cannot be fetched keeps its generated cookie and
is reported, so the case scores as a miss rather than being silently dropped.
"""
import http.cookiejar
import json
import sys
import urllib.parse
import urllib.request

DESER = "InsecureDeserialization/"
LDAP = "LDAPInjectionVulnerability/"
# The form each level's page posts to have its cookie issued.
DESER_FORMS = {
    "LEVEL_1": {"theme": "light", "notificationsEnabled": "false"},
    "LEVEL_2": {},
    "LEVEL_3": {},
    "LEVEL_4": {"section": "home"},
}
LDAP_ACCOUNT = {"username": "alice", "password": "alicePass123"}


def issued_cookies(base, level):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                         urllib.request.ProxyHandler({}))
    data = urllib.parse.urlencode(DESER_FORMS[level]).encode()
    url = "%s/InsecureDeserialization/%s" % (base, level)
    with opener.open(urllib.request.Request(url, data=data, method="POST"), timeout=30) as r:
        r.read()
    return {c.name: c.value for c in jar}


def seed_deser(r, base):
    """Replace the case's placeholder cookie with the one its level issues. Raises on failure."""
    level = r["test"].split("/")[1]
    if level not in DESER_FORMS:
        raise RuntimeError("no issuing form known for %s" % level)
    got = issued_cookies(base, level)
    want = [k for k in (r.get("cookies") or {})]
    missing = [k for k in want if k not in got]
    if not want or missing:
        raise RuntimeError("level did not issue %s (got %s)" % (missing or "a cookie", sorted(got)))
    for k in want:
        r["cookies"][k] = got[k]


def seed_ldap(r):
    """Put the challenge card's account in a login-shaped level. Returns True when rewritten."""
    q = r.get("query")
    if not isinstance(q, dict) or "password" not in q or "username" not in q:
        return False
    q.update(LDAP_ACCOUNT)
    return True


def seed_entry(r, base):
    """Seed one case in place. Returns a failure note, or None."""
    if r["test"].startswith(DESER):
        try:
            seed_deser(r, base)
        except Exception as e:  # noqa: BLE001 - every failure is reported, none is fatal
            return "left as generated: %s" % e
    elif r["test"].startswith(LDAP):
        seed_ldap(r)
    return None


def main():
    src, dst = sys.argv[1], sys.argv[2]
    base = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:9090/VulnerableApp"
    reqs = json.load(open(src))
    for r in reqs:
        note = seed_entry(r, base)
        if note:
            print("%s: %s" % (r["test"], note), file=sys.stderr)
    json.dump(reqs, open(dst, "w"), indent=1)


if __name__ == "__main__":
    main()
