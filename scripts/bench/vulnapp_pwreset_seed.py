#!/usr/bin/env python3
"""Give VulnerableApp's PasswordResetVulnerability seeds a real body (they ship as {type:
PasswordResetRequest} with no example, so the harness sent them empty).

usage: pwreset_seed.py REQUESTS_IN REQUESTS_OUT [GT_IN GT_OUT BASE] [--only-pwreset]

Each PasswordResetVulnerability/LEVEL_N seed becomes the reset REQUEST step,
  POST .../LEVEL_N  {"action":"request","email":"levelN_user1@sasanlabs.org"}
for the level's own test account (the account the target's GET LEVEL_N page documents), with one
companion seeded before it and never audited: the CONFIRM step with a placeholder token,
  POST .../LEVEL_N  {"action":"reset","token":"seed-placeholder","newPassword":"..."}
which is what an operator walking the reset flow through the proxy captures. Prints the identity list
for RESET_IDENTITIES (the scanner's reset_test_identities). BASE (e.g. http://localhost:21690) rewrites the scheme+host of the reset seeds
and of their ground-truth rows, for the private instance that has a mail sink.

VulnerableApp sends the reset link by mail (spring.mail.host, default "mailpit"), and the request
fails with HTTP 500 when no mail server answers. Run mailsink.py and start the app with
  --spring.mail.host=127.0.0.1 --spring.mail.port=<smtp> --vulnerableapp.email.base-url=http://localhost:<app port>
then point reset_mailbox_url at http://127.0.0.1:<http>/inbox?to={identity}.
"""
import json, re, sys

args = [a for a in sys.argv[1:] if not a.startswith('--')]
only = '--only-pwreset' in sys.argv
reqs = json.load(open(args[0]))
base = args[4] if len(args) > 4 else None
out, ids = [], []
for r in reqs:
    if not r['test'].startswith('PasswordResetVulnerability/'):
        if not only:
            out.append(r)
        continue
    url = r['url']
    if base:
        url = re.sub(r'^https?://[^/]+', base, url)
    level = int(re.search(r'LEVEL_(\d+)', url).group(1))
    email = 'level%d_user1@sasanlabs.org' % level
    ids.append(email)
    r = dict(r, url=url, method='POST',
             body={'type': 'json', 'example': {'action': 'request', 'email': email}})
    r['companions'] = [{'test': r['test'] + '#confirm', 'method': 'POST', 'url': url, 'query': {}, 'form': {},
                        'headers': {}, 'cookies': {},
                        'body': {'type': 'json', 'example': {'action': 'reset', 'token': 'seed-placeholder',
                                                             'newPassword': 'SeedPassw0rd!x'}}}]
    out.append(r)
json.dump(out, open(args[1], 'w'), indent=1)
if len(args) > 3:
    gt = json.load(open(args[2]))
    g2 = []
    for g in gt:
        if g['test'].startswith('PasswordResetVulnerability/'):
            if base:
                g = dict(g, url=re.sub(r'^https?://[^/]+', base, g['url']))
            g2.append(g)
        elif not only:
            g2.append(g)
    json.dump(g2, open(args[3], 'w'), indent=1)
print(','.join(ids))
