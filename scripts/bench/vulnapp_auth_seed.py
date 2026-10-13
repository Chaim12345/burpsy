#!/usr/bin/env python3
"""Give OWASP VulnerableApp's AuthenticationVulnerability cases each level's own account name.

usage: vulnapp_auth_seed.py IN_REQUESTS_JSON OUT_REQUESTS_JSON

The generated request list logs in to every AuthenticationVulnerability level as admin/password.
No level has an "admin": each level looks the user up by (username, level) in its own table row
(AuthLoginService: findByUsernameAndLevel), so every captured login is an unknown-user failure. The
username-enumeration check compares the CAPTURED username's answers with invented ones, and an
unknown captured username correctly answers like the invented ones - the check can never fire.

This puts the level's documented account name (the application's own Authentication data.sql, one
row per level) in the username field. The password is left as generated: it is wrong for every
account, the checks replace it with random values anyway, and no real password is ever needed or
sent. The SQL-injection level keeps its account too; the injection is in the same field.

This is benchmark knowledge - the app's family name and seeded accounts - so it lives here and
never in the scanner. Nothing is sent to the application by this script.
"""
import json
import sys

FAMILY = "AuthenticationVulnerability/"
# auth_users (username, level) from src/main/resources/scripts/Authentication/db/data.sql.
LEVEL_ACCOUNTS = {
    "LEVEL_1": "admin_sqli",
    "LEVEL_2": "admin_logs",
    "LEVEL_3": "admin_plain",
    "LEVEL_4": "admin_md5",
    "LEVEL_5": "admin_sha1",
    "LEVEL_6": "admin_sha256",
    "LEVEL_7": "admin_enum",
    "LEVEL_8": "admin_weak",
    "LEVEL_9": "admin_secure",
    "LEVEL_10": "admin_lowcost",
}


def seed_entry(r):
    """Set the level's account name in whichever of query/form carries the username. Returns True
    when the entry was rewritten."""
    level = r["test"].split("/")[1]
    user = LEVEL_ACCOUNTS.get(level)
    if not user:
        return False
    done = False
    for part in ("query", "form"):
        fields = r.get(part)
        if isinstance(fields, dict) and "username" in fields:
            fields["username"] = user
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
