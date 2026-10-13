#!/usr/bin/env python3
"""Give OWASP VulnerableApp's AuthenticationVulnerability cases each level's own working credential.

usage: vulnapp_auth_seed.py IN_REQUESTS_JSON OUT_REQUESTS_JSON

The generated request list logs in to every AuthenticationVulnerability level as admin/password.
No level has an "admin": each level looks the user up by (username, level) in its own table row
(AuthLoginService: findByUsernameAndLevel), so every captured login is an unknown-user failure. The
username-enumeration check compares the CAPTURED username's answers with invented ones, and an
unknown captured username correctly answers like the invented ones - the check can never fire.

A wrong password hides the rest. Levels 3/4/5/6/10 return the stored record (passwordInDB or
passwordHash) only after a SUCCESSFUL login, so the weak-crypto check's "the submitted value's own
digest" and plaintext-storage proofs, which need the captured request to be a working login, could
not fire on any level.

This puts the level's documented account - name AND password, from the comments in the application's
own Authentication data.sql (one row per level) - in the captured request, as a tester does with an
engagement's test account: the operator captures a working login through the proxy. The credentials
go into the seeded request only, never into the scanner's configuration. The SQL-injection level gets
its account too; the injection is in the same field.

Every pair was checked by logging in to the level once (each answers isValid=true).

This is benchmark knowledge - the app's family name and seeded accounts - so it lives here and
never in the scanner. Nothing is sent to the application by this script.
"""
import json
import sys

FAMILY = "AuthenticationVulnerability/"
# auth_users (username, level) and each row's documented password, from
# src/main/resources/scripts/Authentication/db/data.sql.
LEVEL_ACCOUNTS = {
    "LEVEL_1": ("admin_sqli", "not_needed_for_sqli"),
    "LEVEL_2": ("admin_logs", "v9K#2mLp!8zQ"),
    "LEVEL_3": ("admin_plain", "b7X$4nRj-6mW"),
    "LEVEL_4": ("admin_md5", "SaKyb21.20#"),
    "LEVEL_5": ("admin_sha1", "WyXxb@i34"),
    "LEVEL_6": ("admin_sha256", "QoTz8!bM52"),
    "LEVEL_7": ("admin_enum", "RuPq3#kW76"),
    "LEVEL_8": ("admin_weak", "password123"),
    "LEVEL_9": ("admin_secure", "9fG#2hJk*LmN!8qR"),
    "LEVEL_10": ("admin_lowcost", "sunshine"),
}


def seed_entry(r):
    """Set the level's account name and password in whichever of query/form carries the username.
    Returns True when the entry was rewritten (both fields present and set)."""
    level = r["test"].split("/")[1]
    acct = LEVEL_ACCOUNTS.get(level)
    if not acct:
        return False
    user, password = acct
    done = False
    for part in ("query", "form"):
        fields = r.get(part)
        if isinstance(fields, dict) and "username" in fields and "password" in fields:
            fields["username"] = user
            fields["password"] = password
            done = True
    return done


def main():
    src, dst = sys.argv[1], sys.argv[2]
    reqs = json.load(open(src))
    n = 0
    for r in reqs:
        if not r["test"].startswith(FAMILY):
            continue
        if seed_entry(r):
            n += 1
        else:
            print("%s: no username field or no documented account, left as generated" % r["test"],
                  file=sys.stderr)
    json.dump(reqs, open(dst, "w"), indent=1)
    print("seeded %d authentication case(s)" % n, file=sys.stderr)


if __name__ == "__main__":
    main()
