#!/usr/bin/env python3
"""Build vulnapp_requests.json: OWASP VulnerableApp's 168 cases as a request list with ground truth.

usage: vulnapp_build_requests.py SRC_JAVA_DIR SCANNER_JSON ALLENDPOINT_JSON OUTDIR [--base http://localhost:9090]

  SRC_JAVA_DIR       the app's source tree (SasanLabs/VulnerableApp; the committed list is from master 36d1090)
  SCANNER_JSON       GET /VulnerableApp/scanner        (per level: URL, variant, method, vulnerabilityTypes)
  ALLENDPOINT_JSON   GET /VulnerableApp/allEndPoint    (per level: challenge payloads)

Writes OUTDIR/requests.json (copy it over vulnapp_requests.json) and OUTDIR/ground-truth.json. CWEs
come from VulnerabilityType.java, parameter names from the controllers and, where a controller reads
an untyped Map, from the console templates (OVERRIDE). The request list is GENERATED, not seeded: its
cookies, tokens and accounts are placeholders the vulnapp_*_seed.py scripts replace at run time.
full_benchmark.py checks the committed list against the live app's /scanner on every run, so a list
from another app version is refused rather than scored against the wrong ground truth.
"""
import sys, os, re, json, glob
a = sys.argv[1:]; base = 'http://localhost:9090'
if '--base' in a: i = a.index('--base'); base = a[i+1].rstrip('/'); del a[i:i+2]
src, scanner_f, allep_f, out = a
files = {f: open(f, encoding='utf-8').read() for f in glob.glob(src + '/**/*.java', recursive=True)}
consts = {}
for t in files.values():
    for n, v in re.findall(r'\bString\s+([A-Z][A-Z0-9_]*)\s*=\s*"([^"]*)"\s*;', t): consts.setdefault(n, v)
CONST_RE = r'\bString\s+([A-Z][A-Z0-9_]*)\s*=\s*"([^"]*)"\s*;'
local = {}
def cval(expr):
    expr = expr.strip()
    if expr.split('.')[-1] in local: return local[expr.split('.')[-1]]
    if expr.startswith('"'): return expr.strip('"')
    last = expr.split('.')[-1]
    if re.fullmatch(r'LEVEL_\d+', last): return last
    return consts.get(last, expr)
vt = files[[f for f in files if f.endswith('types/VulnerabilityType.java')][0]]
cwe = {n: (int(c), None if w == 'null' else int(w)) for n, c, w in re.findall(r'^\s*(\w+)\(\s*(-?\d+)\s*,\s*(-?\d+|null)\s*\)', vt, re.M)}
SAMPLE = {'ipaddress': '127.0.0.1', 'id': '1', 'fetch': 'true', 'fileName': 'UserInfo.json', 'url': 'http://localhost/',
          'returnTo': '/', 'username': 'admin', 'password': 'password', 'email': 'user@example.com', 'level': 'LEVEL_1',
          'JWT': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.MZiW2KkIRI6GhKsu16Me7-3IpS4nBw1W47CW67QAqS0'}
ann_arg = lambda s, key: (re.search(key + r'\s*=\s*([\w."]+)', s) or [None, None])[1]
params = {}  # (vuln, level, variant) -> dict
for f, t in files.items():
    local = dict(re.findall(CONST_RE, t))
    m = re.search(r'@VulnerableAppRestController\((.*?)\)\s*public class', t, re.S)
    if not m: continue
    vuln = cval(ann_arg(m.group(1), 'value'))
    parts = re.split(r'@VulnerableAppRequestMapping\(', t)[1:]
    for p in parts:
        depth, j = 1, 0
        while depth:
            depth += {'(': 1, ')': -1}.get(p[j], 0); j += 1
        args, rest = p[:j-1], p[j:]
        level = cval(ann_arg(args, 'value') or 'LEVEL_?')
        method = 'POST' if 'RequestMethod.POST' in args else ('PUT' if 'RequestMethod.PUT' in args else 'GET')
        variant = 'SECURE' if 'Variant.SECURE' in args else 'UNSECURE'
        sig = rest[:rest.index('{')]; body = rest[rest.index('{'):]
        r = dict(query={}, headers={}, cookies={}, body=None, path_vars=[])
        for kind, aa, typ, var in re.findall(r'@(RequestParam|RequestHeader|CookieValue|RequestBody|PathVariable)(?:\(([^)]*)\))?\s+(?:final\s+)?([\w.<>, ?\[\]]+?)\s+(\w+)\s*[,)]', sig):
            aa = aa or ''
            name = ann_arg(aa, 'value') or ann_arg(aa, 'name') or (aa.strip() if aa.strip() and '=' not in aa else None)
            name = cval(name) if name else var
            dflt = ann_arg(aa, 'defaultValue')
            if kind == 'RequestParam' and typ.startswith(('Map', 'MultiValueMap')):
                for k in re.findall(var + r'\.get(?:First|OrDefault)?\(\s*([\w."]+)', body): r['query'][cval(k)] = SAMPLE.get(cval(k), 'test')
                continue
            if kind == 'RequestHeader' and typ.startswith(('Map', 'HttpHeaders')): continue
            val = cval(dflt) if dflt else ('1' if typ in ('Integer', 'int', 'Long', 'long') else SAMPLE.get(name, 'test'))
            if typ.startswith('MultipartFile'): r['body'] = {'multipart_file': name}; continue
            tgt = {'RequestParam': 'query', 'RequestHeader': 'headers', 'CookieValue': 'cookies'}.get(kind)
            if tgt: r[tgt][name] = val
            elif kind == 'RequestBody': r['body'] = {'type': typ}
            else: r['path_vars'].append(name)
        params.setdefault((vuln, level, variant), r)
scanner = json.load(open(scanner_f))
allep = {e['Name']: e for e in json.load(open(allep_f))}
# Inputs the controllers read without typed annotations (Map with no .get, raw request body);
# names taken from the console templates under src/main/resources/static/templates.
OVERRIDE = {
 'XSSWithHtmlTagInjection': dict(query={'value': 'test'}),
 'PersistentXSSInHTMLTagVulnerability': dict(query={'comment': 'test'}),
 'SessionManagementVulnerability': dict(query={'action': 'login'}, body={'type': 'json', 'content_type': 'application/json', 'example': {'username': 'admin', 'password': 'password'}}),
 'XXEVulnerability': dict(body={'type': 'xml', 'content_type': 'application/xml', 'example': '<?xml version="1.0"?><book><name>a</name><author>b</author><isbn>1</isbn><publisher>c</publisher><otherComments>d</otherComments></book>'}),
}
truth, reqs, miss, seen = [], [], [], {}
for s in scanner:
    path = s['url'].split('/VulnerableApp/', 1)[1]; vuln, level = path.split('/')[:2]
    url = base + '/VulnerableApp/' + path
    det = next((d for d in (allep.get(vuln) or {}).get('Detailed Information', []) if d['Level'] == level and d['Variant'] == s['variant']), {})
    types = s['vulnerabilityTypes']
    tid = f'{vuln}/{level}/{s["variant"]}'
    seen[tid] = seen.get(tid, 0) + 1
    if seen[tid] > 1: tid += f'#{seen[tid]}'
    entry = dict(test=tid, vulnerability=vuln, level=level, variant=s['variant'], vulnerable=s['variant'] == 'UNSECURE',
                 method=s['method'], url=url, vulnerabilityTypes=types,
                 cwes=sorted({cwe[t][0] for t in types if t in cwe}), wasc=sorted({cwe[t][1] for t in types if t in cwe and cwe[t][1] is not None}),
                 sample_payloads=[c.get('payload', {}).get('value') for c in det.get('ChallengeCard') or [] if c.get('payload')])
    truth.append(entry)
    p = params.get((vuln, level, s['variant'])) or params.get((vuln, level, 'UNSECURE'))
    if p is None: miss.append(entry['test']); p = dict(query={}, headers={}, cookies={}, body=None, path_vars=[])
    if vuln in OVERRIDE and not (p['query'] or p['body'] or p['cookies'] or p['headers']): p = {**p, **OVERRIDE[vuln]}
    q = dict(p['query']); form = {}
    if s['method'] != 'GET' and not p['body']: form, q = q, {}
    reqs.append(dict(test=entry['test'], method=s['method'], url=url, query=q, form=form, headers=p['headers'], cookies=p['cookies'],
                     body=p['body'], variant=s['variant'], vulnerable=entry['vulnerable'], cwes=entry['cwes'], vulnerabilityTypes=types))
os.makedirs(out, exist_ok=True)
json.dump(truth, open(out + '/ground-truth.json', 'w'), indent=1)
json.dump(reqs, open(out + '/requests.json', 'w'), indent=1)
print(len(truth), 'cases; no-param-match:', miss)
