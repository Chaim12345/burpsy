#!/usr/bin/env python3
"""Give OWASP VulnerableApp's session-management cases a working login before they are captured.

usage: vulnapp_session_seed.py IN_REQUESTS_JSON OUT_REQUESTS_JSON

The generated request list posts the placeholder credentials admin/password to every
SessionManagementVulnerability level, which the application refuses, so the captured login sets no
cookie and the scanner's session-management check has no session to examine. This replaces the body
of the levels it covers with the application's own seeded test account (session_user, from the
application's SessionManagement data.sql), which is what a tester would type into the level's page.

Only the session-handling levels are rewritten. The rate-limiting level is left as generated: its
check (a different one) works with invented accounts and must not be handed a real one.

This is benchmark knowledge - the app's family name and test account - so it lives here and never in
the scanner. Nothing is sent to the application by this script.
"""
import json
import sys

ACCOUNT = {"username": "session_user", "password": "password123"}
FAMILY = "SessionManagementVulnerability/"
LEAVE = {"NO_LOGIN_RATE_LIMITING"}


def main():
    src, dst = sys.argv[1], sys.argv[2]
    reqs = json.load(open(src))
    n = 0
    for r in reqs:
        if not r["test"].startswith(FAMILY) or LEAVE & set(r.get("vulnerabilityTypes") or []):
            continue
        body = r.get("body") or {}
        if body.get("type") != "json":
            print("%s: body is not JSON, left as generated" % r["test"], file=sys.stderr)
            continue
        body["example"] = dict(ACCOUNT)
        n += 1
    json.dump(reqs, open(dst, "w"), indent=1)
    print("seeded %d session-management case(s)" % n, file=sys.stderr)


if __name__ == "__main__":
    main()
