#!/usr/bin/env python3
"""Give OWASP VulnerableApp's OTPVulnerability cases a real account and their validate step.

usage: vulnapp_otp_seed.py IN_REQUESTS_JSON OUT_REQUESTS_JSON

The generated request list asks every OTP level for a code for user@example.com, which no level
knows: the level answers its generic "if the account exists" message, sends no mail, and stores no
code. The level's own test account is levelN_user1@sasanlabs.org (OTPUserSeeder), and the code it
mails goes to the benchmark's mail sink (full_benchmark.py starts the app with spring.mail.host
pointing at mailsink.py), so the account is one the harness owns end to end.

Each case's planted defects sit on two steps of one flow: the REQUEST (POST LEVEL_N, email) mints and
mails a code - the weak-random and no-expiry defects are properties of that code - and the VALIDATE
step (POST LEVEL_N/validate, email + otp) is where a code is guessed, so the missing rate limit is
there. The request stays the case's audited exchange; the validate step becomes an AUDITED
companion sent after it ("when": "after", "audit": true), and full_benchmark.py credits a finding
on either exchange to the case. Its otp is a placeholder: the scanner supplies its own values and
never needs the real code.

Prints the accounts, comma-separated, for reset_test_identities: they are mailbox-backed accounts
the harness owns, which is what that setting declares.

This is benchmark knowledge - the app's routes and seeded accounts - so it lives here and never in
the scanner. Nothing is sent to the application by this script.
"""
import json
import sys

FAMILY = "OTPVulnerability/"


def seed_entry(r):
    """Rewrite one OTP case in place; returns the account it now names."""
    level = r["test"].split("/")[1]
    n = int(level.split("_")[1])
    email = "level%d_user1@sasanlabs.org" % n
    form = dict(r.get("form") or {})
    form["email"] = email
    r["form"] = form
    r["companions"] = [{
        "test": r["test"] + "#validate", "method": "POST", "url": r["url"].rstrip("/") + "/validate",
        "query": {}, "form": {"email": email, "otp": "0000"}, "headers": {}, "cookies": {}, "body": None,
        "when": "after", "audit": True,
    }]
    return email


def main():
    src, dst = sys.argv[1], sys.argv[2]
    reqs = json.load(open(src))
    ids = []
    for r in reqs:
        if r["test"].startswith(FAMILY):
            ids.append(seed_entry(r))
    json.dump(reqs, open(dst, "w"), indent=1)
    print(",".join(ids))


if __name__ == "__main__":
    main()
