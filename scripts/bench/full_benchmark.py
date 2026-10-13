#!/usr/bin/env python3
"""The FULL VulnerableApp benchmark in one command, with every check's prerequisites in place.

    sudo python3 scripts/bench/full_benchmark.py --jar /path/VulnerableApp-1.0.0.jar --out /tmp/bench-full

run_vulnapp.py scores the scanner against whatever app and burpsy the caller already started, and
seeds nothing: its JWT, IDOR, session, auth and password-reset cases are measured without the
tokens, accounts and mail server those checks need, so they score as misses for the harness's
reason, not the scanner's. This entry point owns the whole environment instead:

  1. starts mailsink.py, then VulnerableApp as uid 65534 (setpriv) on --app-port, mailing to the
     sink, logging WARN to the console only (no rolling file log), bound to 127.0.0.1, and waits
     until /VulnerableApp/scanner answers. The committed case list is checked against that live
     /scanner, so a list from another app version is refused rather than scored;
  2. seeds one request list (seeded-requests.json): session accounts, password-reset bodies plus
     their confirm companions, each auth level's account, each JWT level's own token, IDOR login
     cookies. Token-bearing cases are re-seeded at send time once older than --reseed-minutes
     (IDOR tokens expire after an hour);
  3. starts one burpsy per worker slot and applies the full profile through the confirmed
     PUT /api/scanner/config: every check_* switch, xss_browser_targets for this app's origin,
     reset_test_identities and reset_mailbox_url. -dom attaches to $BURPSY_DOM_REMOTE when set,
     else launches a local Chrome. The applied config is read back and a key that did not take is
     fatal;
  4. runs every case in the list (168, upload and traversal included; --only narrows it),
     hazardous families last, each seed sent through the burpsy proxy and audited;
  5. scores strict and lenient with posture credit separate (run_vulnapp.py's rules), mapping each
     finding to CWEs through the RUNNING burpsy's own advisory catalogue (/api/advisories), so every
     burpsy-only row (BurpsyNativeRows, type_index 0xb5......) is scored by the CWE its native
     advisory declares, never by a hard-coded table; writes JSON + markdown with a per-category
     table and, given --baseline, a per-case diff;
  6. stops every process it started, and only those, by PID (descendants found through /proc and
     matched on start time, so a recycled PID is never signalled). It never pkills a pattern.

Why uid 65534: VulnerableApp's upload and path-traversal levels write wherever a filename points.
Run as root they overwrote /etc/passwd. As nobody, such a write fails with EACCES and the case still
answers. Run as root, this script refuses to start the app any other way; run as a non-root user
it refuses unless --run-as-current-user says that user's own files may be written to.

Stdlib only. Nothing here is sent anywhere but 127.0.0.1.
"""

import argparse
import base64
import collections
import http.client
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))
import run_vulnapp as rv  # noqa: E402  (scoring rules, XSS browser route)
import vulnapp_auth_seed  # noqa: E402
import vulnapp_idor_seed  # noqa: E402
import vulnapp_jwt_seed  # noqa: E402
import vulnapp_otp_seed  # noqa: E402
import vulnapp_upload_seed  # noqa: E402
from vulnapp_cases import BLANKET_CHECK_NAMES  # noqa: E402

UNPRIV_UID = 65534
CONFIRM = "X-Burpsy-Confirm"
# Families whose probes execute what they are sent or can wedge a request thread; run last so a
# wedged target costs only the cases after it (run_vulnapp.py's HAZARD, by family).
# Cases whose verdict rests on latency or on a burst answering uniformly: blind (time-based) SQL
# injection, and every login-shaped category the rate-limit check bursts. Parallel load skews those
# measurements, so they run in their own low-concurrency lane (--timing-workers), after the main lane
# by default. Request smuggling is timing-based too but is a check, not a case: it runs on every case,
# in whichever lane the case is in.
TIMING_TYPES = {"BLIND_SQL_INJECTION", "NO_LOGIN_RATE_LIMITING", "USERNAME_ENUMERATION"}
TIMING_FAMILIES = {"AuthenticationVulnerability", "OTPVulnerability", "SessionManagementVulnerability"}
HAZARD_TYPES = {"COMMAND_INJECTION", "REMOTE_CODE_EXECUTION", "INSECURE_DESERIALIZATION",
                "DENIAL_OF_SERVICE", "UNCONTROLLED_RESOURCE_CONSUMPTION"}
# Name-level CWE aliases where the app files a class under a sibling of the CWE the advisory uses.
# Burp files web cache poisoning under CWE-436; VulnerableApp under CWE-349. Narrow and explicit.
CWE_ALIASES = {"Web cache poisoning": {349}}
NATIVE_BASE = 0xB5000000

_direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def log(msg):
    sys.stderr.write("[full-bench %s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stderr.flush()


# --------------------------------------------------------------------------------------------------
# Processes: everything this run starts is registered here and stopped by PID.


def _proc_table():
    """{pid: (ppid, starttime)} from /proc."""
    out = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            raw = open("/proc/%s/stat" % d).read()
        except OSError:
            continue
        rest = raw[raw.rindex(")") + 2:].split()
        out[int(d)] = (int(rest[1]), rest[19])
    return out


def _descendants(pid):
    tab = _proc_table()
    kids = collections.defaultdict(list)
    for p, (pp, _) in tab.items():
        kids[pp].append(p)
    found, stack = [], [pid]
    while stack:
        for k in kids.get(stack.pop(), []):
            found.append((k, tab[k][1]))
            stack.append(k)
    return found


def _same_process(pid, starttime):
    try:
        raw = open("/proc/%d/stat" % pid).read()
    except OSError:
        return False
    return raw[raw.rindex(")") + 2:].split()[19] == starttime


class Procs:
    def __init__(self):
        self.lk = threading.Lock()
        self.live = []  # (name, Popen)

    def start(self, name, argv, **kw):
        p = subprocess.Popen(argv, **kw)
        with self.lk:
            self.live.append((name, p))
        log("started %s pid %d" % (name, p.pid))
        return p

    def stop(self, p, grace=10):
        with self.lk:
            entry = next((e for e in self.live if e[1] is p), None)
            if entry:
                self.live.remove(entry)
        name = entry[0] if entry else "pid %d" % p.pid
        if p.poll() is not None:
            return
        kids = _descendants(p.pid)  # before the parent goes, while the tree is still linked
        p.terminate()
        try:
            p.wait(grace)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(5)
        for pid, st in kids:
            if _same_process(pid, st):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        log("stopped %s (pid %d)" % (name, p.pid))

    def stop_all(self):
        with self.lk:
            items = list(reversed(self.live))
        for _, p in items:
            try:
                self.stop(p)
            except Exception as e:  # cleanup keeps going
                log("could not stop pid %d: %s" % (p.pid, e))


PROCS = Procs()
STOP = threading.Event()  # set on a signal or a fatal error: workers stop taking cases


def _on_signal(signum, _frame):
    raise SystemExit(128 + signum)


# --------------------------------------------------------------------------------------------------
# Small HTTP helpers (never through any proxy unless asked).


def get(url, timeout=10):
    with _direct.open(url, timeout=timeout) as r:
        return r.status, r.read()


def port_in_use(port):
    s = socket.socket()
    s.settimeout(0.5)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


def wait_until(pred, timeout, what, proc=None):
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError("%s: the process exited with %s before it was ready" % (what, proc.returncode))
        try:
            if pred():
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError("%s: not ready after %ds" % (what, timeout))


class API:
    def __init__(self, web):
        self.web = web

    def call(self, method, path, body=None, headers=None, timeout=30):
        data = None if body is None else (body if isinstance(body, bytes) else body.encode())
        req = urllib.request.Request(self.web + path, data=data, method=method, headers=headers or {})
        with _direct.open(req, timeout=timeout) as r:
            raw = r.read()
        return json.loads(raw) if raw else None

    def confirmed(self, method, path, body, timeout=30, extra=None):
        """A gated call: mint the token for the exact body bytes, then send them."""
        call = json.dumps({"method": method, "url": path, "body": body})
        tok = self.call("POST", "%s/confirm" % path if not path.startswith("/api/audit/") else "/api/audit/confirm",
                        call, {"Content-Type": "application/json"})["token"]
        hdr = {CONFIRM: tok}
        if body:
            hdr["Content-Type"] = "application/json"
        hdr.update(extra or {})
        return self.call(method, path, body or None, hdr, timeout=timeout)


# --------------------------------------------------------------------------------------------------
# 1. mail sink + VulnerableApp


LOG4J2 = """<?xml version="1.0" encoding="UTF-8"?>
<!-- Written by full_benchmark.py. The jar's own log4j2.xml logs DEBUG to a rolling ./logs/server.log
     whatever spring's logging.file.* says (measured: 14 MB within minutes under benchmark load,
     ~3 GB every few hours at INFO). This replaces it: WARN, console only, no file appender. -->
<Configuration>
  <Appenders><Console name="CONSOLE" target="SYSTEM_OUT"><PatternLayout pattern="%d %-5p %c{1} - %m%n"/></Console></Appenders>
  <Loggers><Root level="WARN"><AppenderRef ref="CONSOLE"/></Root></Loggers>
</Configuration>
"""


def start_mailsink(a, out):
    p = PROCS.start("mailsink", [sys.executable, "-I", str(HERE / "mailsink.py"), str(a.smtp_port), str(a.inbox_port)],
                    stdout=open(out / "mailsink.log", "w"), stderr=subprocess.STDOUT)
    wait_until(lambda: get("http://127.0.0.1:%d/health" % a.inbox_port, 2)[0] == 200, 20, "mail sink", p)
    return p


def start_vulnapp(a, out):
    unpriv = os.geteuid() == 0
    if not unpriv and not a.run_as_current_user:
        raise SystemExit("VulnerableApp must run as uid %d and only root can switch to it. Run this as root, or pass "
                         "--run-as-current-user to accept that its upload/traversal levels may write to %s's files."
                         % (UNPRIV_UID, pwd.getpwuid(os.geteuid()).pw_name))
    # The run directory's whole path must be traversable by uid 65534: Spring Boot's launcher reopens
    # the jar by its absolute path, and a 0700 ancestor (a per-user temp root) makes it fail with
    # ClassNotFoundException: JarLauncher. A fresh directory directly under /tmp always qualifies.
    va = Path(tempfile.mkdtemp(prefix="burpsy-vulnapp-%d-" % a.app_port, dir=a.va_parent))
    os.chmod(va, 0o755)
    jar = va / "VulnerableApp.jar"
    try:
        os.link(a.jar, jar)  # no 64 MB copy when the jar is on the same filesystem
    except OSError:
        shutil.copyfile(a.jar, jar)
        os.chmod(jar, 0o644)
    (va / "log4j2-bench.xml").write_text(LOG4J2)
    for d in ("home", "tmp"):
        (va / d).mkdir()
        if unpriv:
            os.chown(va / d, UNPRIV_UID, UNPRIV_UID)
    drop = ["setpriv", "--reuid=%d" % UNPRIV_UID, "--regid=%d" % UNPRIV_UID, "--clear-groups"] if unpriv else []
    if unpriv and subprocess.call(drop + ["test", "-r", str(jar)]) != 0:
        raise SystemExit("uid %d cannot read %s; check the permissions on its path" % (UNPRIV_UID, jar))
    argv = drop + [
        "java", "-Xmx%s" % a.java_xmx,
        "-Duser.home=%s" % (va / "home"), "-Djava.io.tmpdir=%s" % (va / "tmp"),
        "-Dlog4j2.configurationFile=%s" % (va / "log4j2-bench.xml"),
        "-jar", str(jar),
        "--server.port=%d" % a.app_port, "--server.address=127.0.0.1",
        "--spring.mail.host=127.0.0.1", "--spring.mail.port=%d" % a.smtp_port,
        "--vulnerableapp.email.base-url=http://%s:%d" % (a.app_host, a.app_port),
        "--logging.config=%s" % (va / "log4j2-bench.xml"),
        "--logging.level.root=WARN", "--logging.level.org.springframework.web=WARN",
        "--logging.level.org.hibernate=WARN",
    ]
    console = open(a.app_console_log, "w") if a.app_console_log else subprocess.DEVNULL
    env = dict(os.environ, HOME=str(va / "home"))
    p = PROCS.start("vulnapp", argv, cwd=str(va), env=env, stdout=console, stderr=subprocess.STDOUT)
    if unpriv:
        time.sleep(1)
        uids = [ln for ln in open("/proc/%d/status" % p.pid) if ln.startswith("Uid:")]
        if not uids or set(uids[0].split()[1:]) != {str(UNPRIV_UID)}:
            PROCS.stop(p)
            raise SystemExit("VulnerableApp is not running as uid %d (%s); stopped it" % (UNPRIV_UID, uids))
    base = "http://%s:%d" % (a.app_host, a.app_port)
    wait_until(lambda: get(base + "/VulnerableApp/scanner", 5)[0] == 200, a.app_start_timeout,
               "VulnerableApp on %s (rerun with --app-console-log FILE to see why)" % base, p)
    log("VulnerableApp ready on %s as uid %d, run dir %s" % (base, os.geteuid() if not unpriv else UNPRIV_UID, va))
    return p, va


def app_alive(base):
    for _ in range(2):
        try:
            if get(base + "/VulnerableApp/scanner", 5)[0] == 200:
                return True
        except Exception:
            time.sleep(2)
    return False


# --------------------------------------------------------------------------------------------------
# 2. seeding


def check_list_matches_app(reqs, base):
    """The committed list's (path, variant, method, types) multiset must equal the live /scanner."""
    live = json.loads(get(base + "/VulnerableApp/scanner", 30)[1])
    key = lambda u, v, m, t: (u.split("/VulnerableApp/", 1)[1], v, m, tuple(t))  # noqa: E731
    want = collections.Counter(key(s["url"], s["variant"], s["method"], s["vulnerabilityTypes"]) for s in live)
    have = collections.Counter(key(r["url"], r["variant"], r["method"], r["vulnerabilityTypes"]) for r in reqs)
    return sorted(map(str, (want - have).elements())), sorted(map(str, (have - want).elements()))


def rebase(reqs, base):
    for r in reqs:
        u = urllib.parse.urlsplit(r["url"])
        r["url"] = urllib.parse.urlunsplit(("http", urllib.parse.urlsplit(base).netloc, u.path, u.query, ""))
    return reqs


def family(test):
    return test.split("/")[0]


def refresh_entry(r, app_vbase):
    """Re-fetch the token a token-bearing entry carries. Raises on failure."""
    fam = family(r["test"])
    if fam == "IDORVulnerability":
        r["cookies"] = vulnapp_idor_seed.login(app_vbase, r["test"].split("/")[1])
    elif fam == "JWTVulnerability":
        vulnapp_jwt_seed.seed_entry(r, app_vbase)
    else:
        return
    r["seeded_at"] = time.time()


def seed_all(reqs, app_base, work):
    """Run every seeder over reqs. Returns (seeded list, reset identities, seed failures)."""
    vbase = app_base + "/VulnerableApp"
    fails = []
    src = work / "seed-0-generated.json"
    json.dump(reqs, open(src, "w"), indent=1)
    s1 = work / "seed-1-session.json"
    s2 = work / "seed-2-pwreset.json"
    # The session and password-reset seeders are CLI contracts (the pwreset one runs at import);
    # they are called as documented, not re-implemented.
    r1 = subprocess.run([sys.executable, "-I", str(HERE / "vulnapp_session_seed.py"), str(src), str(s1)],
                        capture_output=True, text=True)
    if r1.returncode:
        raise SystemExit("session seeder failed: %s" % r1.stderr)
    r2 = subprocess.run([sys.executable, "-I", str(HERE / "vulnapp_pwreset_seed.py"), str(s1), str(s2)],
                        capture_output=True, text=True)
    if r2.returncode:
        raise SystemExit("password-reset seeder failed: %s" % r2.stderr)
    for line in (r1.stderr + r2.stderr).splitlines():
        if "left as generated" in line:
            fails.append({"seeder": "session/pwreset", "note": line})
    identities = [x for x in r2.stdout.strip().split(",") if x]
    out = json.load(open(s2))
    for r in out:
        fam = family(r["test"])
        if fam == "AuthenticationVulnerability" and not vulnapp_auth_seed.seed_entry(r):
            fails.append({"test": r["test"], "seeder": "auth", "note": "no username field or account"})
        if fam == "OTPVulnerability":
            acct = vulnapp_otp_seed.seed_entry(r)
            if acct not in identities:
                identities.append(acct)
        if fam == "UnrestrictedFileUpload" and not vulnapp_upload_seed.seed_entry(r):
            fails.append({"test": r["test"], "seeder": "upload", "note": "no multipart file part"})
        if fam in ("IDORVulnerability", "JWTVulnerability"):
            try:
                refresh_entry(r, vbase)
            except Exception as e:
                fails.append({"test": r["test"], "seeder": fam, "note": "left as generated: %s" % e})
    return out, identities, fails


# --------------------------------------------------------------------------------------------------
# 3. burpsy + the full profile


def abilities(a, dom, dom_note):
    """[(ability, "RUN"|"SKIPPED", detail)] for the capabilities behind the switches. Every check_*
    switch is ON whatever this says; a SKIPPED ability is one whose checks are switched on and can
    only report that the capability is missing."""
    out = []
    if dom:
        out.append(("DOM engine (check_dom, check_xss_browser_confirm)", "RUN", dom_note or dom))
    else:
        out.append(("DOM engine (check_dom, check_xss_browser_confirm)", "SKIPPED",
                    "--no-dom" if a.no_dom else "no reachable shared Chrome and no local Chrome/Chromium (--chrome)"))
    if a.collaborator_server:
        out.append(("out-of-band collaborator (check_out_of_band, OOB SQLi/XXE/SSRF)", "RUN",
                    "-collaborator-server %s, client %s" % (a.collaborator_server, a.collaborator_client or "interactsh-client on PATH")))
    else:
        out.append(("out-of-band collaborator (check_out_of_band, OOB SQLi/XXE/SSRF)", "SKIPPED",
                    "no collaborator given: burpsy's only collaborator is the external interactsh-client binary "
                    "(no in-process endpoint; the tests' fake provider is test-only). Pass --collaborator-client "
                    "PATH (the public pool by default) or --collaborator-server URL to run it"))
    out.append(("BCheck corpus (check_corpus)", "RUN",
                "--bchecks %s" % a.bchecks if a.bchecks else "the bundled PortSwigger corpus (attached when no -bchecks is given)"))
    out.append(("password-reset mailbox (check_password_reset)", "RUN",
                "mailsink.py SMTP %d, inbox http://127.0.0.1:%d" % (a.smtp_port, a.inbox_port)))
    return out


DOM_SWITCHES = ("check_dom", "check_xss_browser_confirm")
DOM_SCOPED_OFF = ("scoped off by --dom-off-categories: these categories were audited without the DOM engine "
                  "at the operator's request (no longer needed for any known defect; see README)")


def profile_body(api, a, identities, withheld):
    """EVERY check_* boolean the running binary reports, ON (read at run time, so a new switch cannot
    be missed), but those withheld for a category (--dom-off-categories); plus the routes and
    identities the checks need."""
    cur = api.call("GET", "/api/scanner/config")
    body = {k: k not in withheld for k, v in cur.items() if k.startswith("check_") and isinstance(v, bool)}
    body["probe_timeout_ms"] = a.probe_timeout_ms
    route = dict(rv.VULNAPP_XSS_BROWSER_TARGETS[0])
    route["match"] = a.app_host
    route["root_url"] = "http://%s:%d/VulnerableApp/" % (a.app_host, a.app_port)
    body["xss_browser_targets"] = [route]
    body["reset_test_identities"] = identities
    body["reset_mailbox_url"] = "http://127.0.0.1:%d/inbox?to={identity}" % a.inbox_port
    # --rows: only the checks that can report these rows run (only_rows on /api/scanner/config); every
    # other check is skipped by the scanner and sends nothing. The switches above stay ON so the rows'
    # own families are never the reason a row is missing. Scoring is unchanged.
    if a.rows:
        body["only_rows"] = a.rows
    return body


def apply_profile(api, body):
    raw = json.dumps(body, separators=(",", ":"))
    api.confirmed("PUT", "/api/scanner/config", raw)
    got = api.call("GET", "/api/scanner/config")
    bad = sorted(k for k, v in body.items()
                 if k != "xss_browser_targets" and got.get(k) != v)
    if bad:
        raise RuntimeError("scanner config did not take: %s" % bad)
    if len(got.get("xss_browser_targets") or []) != len(body["xss_browser_targets"]):
        raise RuntimeError("xss_browser_targets did not take: %r" % got.get("xss_browser_targets"))
    return got


NATIVE_DIR = REPO / "burpsy-go" / "internal" / "advisory" / "native"


def advisory_cwe_map(api):
    """{type_index int: {"name", "cwes"}} from the running burpsy's own advisory catalogue.

    /api/advisories lists Burp's 183 catalogue rows only; burpsy's own rows (BurpsyNativeRows) are
    served by /api/advisories/{index} but not listed. Their indices come from the native advisory
    definitions in this checkout (internal/advisory/native/<index>_<Name>.json), and each is asked of
    the RUNNING binary, so a row this binary does not carry is not counted and its CWE is the one the
    binary itself declares."""
    idx = api.call("GET", "/api/advisories", timeout=60)
    want = [row["type_index"] for row in idx.get("advisories") or []]
    want += sorted({f.name.split("_")[0] for f in NATIVE_DIR.glob("b5*_*.json")})
    out = {}
    for ti in want:
        try:
            d = api.call("GET", "/api/advisories/%s" % ti)
        except urllib.error.HTTPError:
            continue  # not in this binary
        out[int(ti, 16)] = {"name": d.get("name"), "cwes": sorted(rv.finding_cwes({"advisory": d}))}
    return out


def send_seed(r, pport):
    """Send one request-list entry through the burpsy proxy at pport. Returns (status, note)."""
    u = urllib.parse.urlsplit(r["url"])
    enc = lambda v: v if isinstance(v, str) else urllib.parse.urlencode(v or {}, doseq=True)  # noqa: E731
    q = "&".join(x for x in (u.query, enc(r.get("query"))) if x)
    hdrs = [("Host", u.netloc), ("User-Agent", "Mozilla/5.0 (burpsy-full-benchmark)"), ("Accept", "*/*")]
    hdrs += list((r.get("headers") or {}).items())
    if r.get("cookies"):
        hdrs.append(("Cookie", "; ".join("%s=%s" % kv for kv in r["cookies"].items())))
    body, ctype, note = None, None, None
    b = r.get("body")
    if r.get("form"):
        body, ctype = enc(r["form"]).encode(), "application/x-www-form-urlencoded"
    elif b and "multipart_file" in b:
        bd = "burpsybenchboundary7d1"
        content = base64.b64decode(b["content_b64"]) if b.get("content_b64") else b"hello"
        body = (('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: %s\r\n\r\n'
                 % (bd, b["multipart_file"], b.get("filename", "test.txt"), b.get("content_type", "text/plain"))).encode()
                + content + ("\r\n--%s--\r\n" % bd).encode())
        ctype = "multipart/form-data; boundary=" + bd
    elif b and b.get("type") in ("json", "xml") and "example" in b:
        ex = b["example"]
        body = (ex if isinstance(ex, str) else json.dumps(ex)).encode()
        ctype = b.get("content_type") or ("application/json" if b["type"] == "json" else "application/xml")
    elif b:
        note = "body_unbuilt: %s" % json.dumps(b)[:200]
    if body is not None:
        if not any(k.lower() == "content-type" for k, _ in hdrs):
            hdrs.append(("Content-Type", ctype))
        hdrs.append(("Content-Length", str(len(body))))
    c = http.client.HTTPConnection("127.0.0.1", pport, timeout=60)
    c.putrequest(r.get("method", "GET"), urllib.parse.urlunsplit(("http", u.netloc, u.path or "/", q, "")),
                 skip_host=True, skip_accept_encoding=True)
    for k, v in hdrs:
        c.putheader(k, v)
    c.endheaders(body)
    resp = c.getresponse()
    resp.read()
    c.close()
    return resp.status, note


class Run:
    def __init__(self, a, out, burpsy, dom, by_test, app_base):
        self.a, self.out, self.burpsy, self.dom = a, out, burpsy, dom
        self.by_test, self.app_base = by_test, app_base
        self.vbase = app_base + "/VulnerableApp"
        # Two lanes, two disjoint slot pools (each slot is a port pair): the main lane and the
        # timing lane (TIMING_TYPES), which never share a port even when they run alongside.
        self.slots = {"main": list(range(a.workers)),
                      "timing": list(range(a.workers, a.workers + a.timing_workers))}
        self.lk = threading.Lock()
        self.profile = None
        self.advisories = None
        self.identities = []
        self.withheld = {}
        self.app_dead = False
        (out / "chunks").mkdir(exist_ok=True)
        (out / "ca").mkdir(exist_ok=True)

    def chunk(self, cid, names, with_dom, lane):
        if STOP.is_set():
            return {"audits": [{"test": n, "error": "not attempted: the run was stopped"} for n in names],
                    "issues": {"findings": []}}
        with self.lk:
            slot = self.slots[lane].pop()
        try:
            return self._chunk(cid, names, slot, with_dom)
        finally:
            with self.lk:
                self.slots[lane].append(slot)

    def _chunk(self, cid, names, slot, with_dom):
        a = self.a
        pport = a.burpsy_base_port + 2 * slot
        api = API("http://127.0.0.1:%d" % (pport + 1))
        argv = [self.burpsy, "-proxy", "127.0.0.1:%d" % pport, "-web", "127.0.0.1:%d" % (pport + 1),
                "-scope-include", a.app_host, "-ca-dir", str(self.out / "ca")]
        withheld = dict(self.withheld)
        if self.dom and with_dom:
            argv += ["-dom", self.dom]
        elif self.dom:
            withheld.update({k: DOM_SCOPED_OFF for k in DOM_SWITCHES})
        if a.bchecks:
            argv += ["-bchecks", a.bchecks]
        if a.collaborator_server:
            argv += ["-collaborator-server", a.collaborator_server,
                     "-collaborator-state-dir", ""]  # a fresh identity per instance, nothing kept in $HOME
            if a.collaborator_client:
                argv += ["-collaborator-client", a.collaborator_client]
        srvlog = open(self.out / "chunks" / ("%s.srv.log" % cid), "w")
        srv = PROCS.start("burpsy[%s]" % cid, argv, stdout=srvlog, stderr=subprocess.STDOUT)
        audits = []
        try:
            try:
                wait_until(lambda: api.call("GET", "/api/stats", timeout=3) is not None, 60, "burpsy %s" % cid, srv)
                got = apply_profile(api, profile_body(api, a, self.identities, withheld))
            except Exception as e:
                # Every case of the chunk is reported untestable with the reason; the run goes on.
                for n in names:
                    audits.append({"test": n, "error": "burpsy not started with the full profile: %s" % e})
                return self._save(cid, audits, {"findings": []})
            with self.lk:
                if self.profile is None:
                    self.profile = got
                need_adv = self.advisories is None
                if need_adv:
                    self.advisories = {}  # claimed; filled below
            if need_adv:
                try:
                    self.advisories = advisory_cwe_map(api)
                except Exception as e:
                    log("advisory catalogue not read: %s" % e)
            for n in names:
                audits.append(self._case(api, pport, n))
            issues = api.call("GET", "/api/issues", timeout=300)
            return self._save(cid, audits, issues)
        finally:
            PROCS.stop(srv)

    def _case(self, api, pport, name):
        r = self.by_test[name]
        rec = {"test": name}
        if STOP.is_set():
            rec["error"] = "not attempted: the run was stopped"
            return rec
        if self.app_dead or not app_alive(self.app_base):
            self.app_dead = True
            rec["error"] = "not attempted: the target stopped answering"
            return rec
        try:
            if r.get("seeded_at") and time.time() - r["seeded_at"] > self.a.reseed_minutes * 60:
                refresh_entry(r, self.vbase)
                rec["reseeded"] = True
            comps = r.get("companions") or []
            # Companions sent BEFORE the case (a reset flow's confirm step) are older than its
            # exchange, so "newest matching row" is the case itself; those sent AFTER it (an OTP
            # validate step) have their own path. An "audit": true companion is audited too and its
            # findings are credited to the case.
            for comp in [c for c in comps if c.get("when") != "after"]:
                rec.setdefault("companion_status", []).append(send_seed(comp, pport)[0])
            rec["seed_status"], note = send_seed(r, pport)
            if note:
                rec["seed_note"] = note
            xid = self._newest(api, r)
            rec["exchange_id"] = xid
            audited = [xid]
            for comp in [c for c in comps if c.get("when") == "after"]:
                rec.setdefault("companion_status", []).append(send_seed(comp, pport)[0])
                if comp.get("audit"):
                    cx = self._newest(api, comp)
                    rec.setdefault("companion_exchange_ids", []).append(cx)
                    audited.append(cx)
            t0 = time.time()
            for x in audited:
                body = api.confirmed("POST", "/api/audit/%d" % x, "", timeout=self.a.audit_timeout)
                rec.setdefault("summaries", []).append(body.get("summary"))
                rec.setdefault("dispositions", []).append([d for d in body.get("dispositions") or [] if d.get("count")])
            rec["secs"] = round(time.time() - t0, 1)
            rec["summary"] = rec["summaries"][0]
        except Exception as e:  # recorded per case, never dropped
            rec["error"] = "%s: %s" % (type(e).__name__, e)
        log("%s %s" % ("?" if "error" in rec else ".", name))
        return rec

    @staticmethod
    def _newest(api, r):
        """The newest captured exchange with r's method and path."""
        want = urllib.parse.urlsplit(r["url"]).path
        rows = [h for h in api.call("GET", "/api/history?limit=50")
                if h["method"] == r.get("method", "GET") and h["path"].split("?")[0] == want]
        if not rows:
            raise RuntimeError("%s was not captured as an exchange (out of scope?)" % r["test"])
        return max(h["id"] for h in rows)

    def _save(self, cid, audits, issues):
        d = {"audits": audits, "issues": issues}
        json.dump(d, open(self.out / "chunks" / ("%s.json" % cid), "w"))
        return d


# --------------------------------------------------------------------------------------------------
# 5. scoring


def finding_view(f, adv):
    """The finding with its CWE set completed from the running binary's advisory catalogue."""
    cwes = set(rv.finding_cwes(f))
    ti = (f.get("advisory") or {}).get("type_index")
    if ti:
        cwes |= set(adv.get(int(ti, 16), {}).get("cwes", ()))
    for nm in (f.get("check_name"), f.get("issue_name"), (f.get("advisory") or {}).get("name")):
        cwes |= CWE_ALIASES.get(nm, set())
    g = dict(f)
    g["advisory"] = dict(f.get("advisory") or {}, classifications=[{"title": "CWE-%d" % c} for c in sorted(cwes)])
    g["_cwes"] = sorted(cwes)
    return g


def request_key(r):
    """What the scanner was given for a case: every field send_seed turns into bytes."""
    return json.dumps({k: r.get(k) for k in ("method", "url", "query", "form", "headers", "cookies", "body", "companions")},
                      sort_keys=True, default=str)


def score(reqs_by_test, chunks, adv, order):
    audits, per_ex, per_path = {}, collections.defaultdict(list), collections.defaultdict(list)
    for ci, d in enumerate(chunks):
        x2t = {a.get("exchange_id"): a["test"] for a in d["audits"] if "exchange_id" in a}
        for a in d["audits"]:
            for cx in a.get("companion_exchange_ids") or []:
                x2t[cx] = a["test"]
        for a in d["audits"]:
            audits[a["test"]] = a
        for f in (d.get("issues") or {}).get("findings") or []:
            g = finding_view(f, adv)
            for o in f.get("occurrences") or []:
                t = x2t.get(o.get("exchange_id"))
                if t:
                    per_ex[t].append(g)
                per_path[(ci, (o.get("path") or "").split("?")[0])].append(g)
    chunk_of = {a["test"]: ci for ci, d in enumerate(chunks) for a in d["audits"]}
    # Cases the app lists more than once for one level (LEVEL_4 and LEVEL_4#2: one per AttackVector)
    # are seeded into byte-identical requests. The scanner is given the same input twice, and a
    # finding it deduplicates (the weak-HMAC row cracks one signing input once) lands on whichever
    # exchange came first, so which of the twins "found" it was an accident of chunk order. Their
    # findings are pooled: identical input, identical evidence. Only audited twins are pooled, and
    # the row says it was.
    twins = collections.defaultdict(list)
    for name in order:
        a = audits.get(name)
        if a is not None and "error" not in a:
            twins[request_key(reqs_by_test[name])].append(name)
    rows, untestable = [], []
    for name in order:
        r = reqs_by_test[name]
        a = audits.get(name)
        if a is None or "error" in a:
            untestable.append({"test": name, "reason": (a or {}).get("error", "never audited")})
            continue
        res, matched_by = per_ex.get(name), "exchange"
        pooled = [t for t in twins[request_key(r)] if t != name]
        if pooled:
            res = list(res or []) + [f for t in pooled for f in per_ex.get(t, [])]
        if not res:
            res = per_path.get((chunk_of[name], urllib.parse.urlsplit(r["url"]).path), [])
            matched_by = "path" if res else "none"
        # One finding per (check, type) for the verdict; occurrences can repeat a finding.
        res = list({(f.get("check_name"), (f.get("advisory") or {}).get("type_index")): f for f in res}.values())
        types = r["vulnerabilityTypes"]
        unsecure = r["variant"] != "SECURE"
        det = rv.detection_hits(res, types)
        post = rv.posture_hits(res, types)
        blanket = [f for f in res if f["check_name"] in BLANKET_CHECK_NAMES]
        hit_s, hit_l = bool(det), bool(det or post or blanket)
        verdict = lambda h: ("TP" if h else "FN") if unsecure else ("FP" if h else "TN")  # noqa: E731
        rows.append({
            "test": name, "category": family(name), "variant": r["variant"], "types": types,
            "case_cwes": sorted(rv.family_cwes(types)),
            "strict": verdict(hit_s), "lenient": verdict(hit_l),
            "posture_only": not det and bool(post),
            "matched": sorted({f["check_name"] for f in det}),
            "findings": sorted({"%s %s" % (f["check_name"], f["_cwes"]) for f in res}),
            "matched_by": matched_by, "pooled_with": pooled, "seed_status": a.get("seed_status"), "seed_note": a.get("seed_note"),
            "reseeded": a.get("reseeded", False), "audit_secs": a.get("secs"),
        })
    return rows, untestable


def tally(rows, key):
    c = collections.Counter(r[key] for r in rows)
    tp, fn, tn, fp = c["TP"], c["FN"], c["TN"], c["FP"]
    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"tp": tp, "fn": fn, "tn": tn, "fp": fp, "tpr": round(100 * tpr, 1), "fpr": round(100 * fpr, 1),
            "score": round(100 * (tpr - fpr), 1)}


def load_baseline(path):
    """{test: strict verdict} from this script's JSON, or score_va.py's -raw.jsonl."""
    p = Path(path)
    if p.suffix == ".jsonl":
        return {j["test"]: j["result"] for j in map(json.loads, p.read_text().splitlines()) if j.strip()}
    d = json.loads(p.read_text())
    return {r["test"]: r["strict"] for r in d.get("per_case", [])}


def diff(rows, untestable, base):
    now = {r["test"]: r["strict"] for r in rows}
    now.update({u["test"]: "untestable" for u in untestable})
    changes = []
    for t in sorted(set(now) | set(base)):
        b, n = base.get(t, "absent"), now.get(t, "absent")
        if b != n:
            changes.append({"test": t, "baseline": b, "now": n})
    cats = collections.defaultdict(lambda: collections.Counter())
    for t, v in base.items():
        cats[family(t)]["base_" + v] += 1
    for t, v in now.items():
        cats[family(t)]["now_" + v] += 1
    return changes, {k: dict(v) for k, v in sorted(cats.items())}


def write_report(out, meta, rows, untestable, adv, baseline_path):
    cats = collections.OrderedDict()
    for r in sorted(rows, key=lambda r: r["category"]):
        cats.setdefault(r["category"], []).append(r)
    unt = collections.Counter(family(u["test"]) for u in untestable)
    by_cat = {}
    for c in sorted(set(cats) | set(unt)):
        rs = cats.get(c, [])
        by_cat[c] = {"cases": len(rs) + unt[c], "untestable": unt[c], "strict": tally(rs, "strict"),
                     "lenient": tally(rs, "lenient"),
                     "posture_only": sum(1 for r in rs if r["posture_only"] and r["variant"] != "SECURE")}
    by_type = collections.defaultdict(list)
    for r in rows:
        for t in r["types"]:
            by_type[t].append(r)
    native = {"%08x" % k: v for k, v in sorted(adv.items()) if k >= NATIVE_BASE}
    report = dict(meta)
    report.update({
        "strict": tally(rows, "strict"), "lenient": tally(rows, "lenient"),
        "posture_credit": {"unsecure_cases_posture_only": sum(1 for r in rows if r["posture_only"] and r["variant"] != "SECURE"),
                           "secure_cases_posture_hit": sum(1 for r in rows if r["posture_only"] and r["variant"] == "SECURE")},
        "by_category": by_cat,
        "by_type": {t: tally(rs, "strict") for t, rs in sorted(by_type.items())},
        "untestable": untestable,
        "native_rows_scored": native,
        "per_case": rows,
    })
    if baseline_path:
        changes, cat_cmp = diff(rows, untestable, load_baseline(baseline_path))
        report["baseline"] = {"path": str(baseline_path), "changes": changes, "by_category": cat_cmp}
    (out / "report.json").write_text(json.dumps(report, indent=1))

    S, L = report["strict"], report["lenient"]
    md = ["# VulnerableApp full benchmark - %s" % meta["started"], "",
          "- burpsy: `%s`; app: %s (uid %s); cases run: %d of %d in the list%s" % (
              meta["burpsy"], meta["app"], meta["app_uid"], meta["cases_selected"], meta["cases_in_list"],
              (" (only: %s)" % ", ".join(meta["only"])) if meta["only"] else ""),
          "- **strict** (detection only): TP %d / FN %d / TN %d / FP %d - TPR %.1f%%, FPR %.1f%%, score **%.1f**"
          % (S["tp"], S["fn"], S["tn"], S["fp"], S["tpr"], S["fpr"], S["score"]),
          "- lenient (+ posture and blanket rows): TP %d / FN %d / TN %d / FP %d - score %.1f"
          % (L["tp"], L["fn"], L["tn"], L["fp"], L["score"]),
          "- posture credit (NOT in either score's detection count): %d unsecure case(s) answered only by a "
          "posture row; the same rows fired on %d secure case(s)" % (
              report["posture_credit"]["unsecure_cases_posture_only"], report["posture_credit"]["secure_cases_posture_hit"]),
          "- untestable (never scored as a pass or a miss): %d" % len(untestable),
          ] + (["- **rows limited to: %s** (only_rows: every other check was skipped and sent nothing; "
                "a miss of an unlisted row is the selection, not the scanner)" % "; ".join(meta["only_rows"])]
               if meta.get("only_rows") else []) + [
          "- wall time for the cases: %ss at %d workers (main lane %ss); timing lane %ss at %d workers, %s" % (
              meta["wall_time"]["cases_secs"], meta["workers"], meta["wall_time"]["lanes_secs"].get("main"),
              meta["wall_time"]["lanes_secs"].get("timing"), meta["timing_workers"], meta["timing_lane"]),
          "- reset/OTP identities: %d; mailbox: %s" % (len(meta["reset_test_identities"]), meta["reset_mailbox_url"]),
          "- check switches ON: %d of %d (%s)%s" % (
              len(meta["checks_on"]), len(meta["checks_on"]) + len(meta["checks_off"]),
              "every check_* key the binary reports" if not meta["checks_off"] else "OFF: " + ", ".join(meta["checks_off"]),
              "" if meta["checks_on"] else " - NO PROFILE WAS APPLIED"),
          "- burpsy-only rows scored by their advisory CWE: %d" % len(native),
          "", "## Abilities", "", "| Ability | Status | Detail |", "|---|---|---|"]
    md += ["| %s | **%s** | %s |" % (x["ability"], x["status"], x["detail"]) for x in meta["abilities"]]
    md += [""]
    if meta["not_set_up"]:
        md += ["## Notes", ""] + ["- %s" % n for n in meta["not_set_up"]] + [""]
    md += ["## By category", "",
           "| Category | Cases | Untestable | TP | FN | TN | FP | TPR | FPR | Lenient TP/FP | Posture-only |",
           "|---|---|---|---|---|---|---|---|---|---|---|"]
    for c, v in by_cat.items():
        s, l2 = v["strict"], v["lenient"]
        md.append("| %s | %d | %d | %d | %d | %d | %d | %.0f%% | %.0f%% | %d/%d | %d |" % (
            c, v["cases"], v["untestable"], s["tp"], s["fn"], s["tn"], s["fp"], s["tpr"], s["fpr"], l2["tp"], l2["fp"],
            v["posture_only"]))
    md += ["", "## By vulnerability type (strict)", "", "| Type | TP | FN | TN | FP |", "|---|---|---|---|---|"]
    for t, s in report["by_type"].items():
        md.append("| %s | %d | %d | %d | %d |" % (t, s["tp"], s["fn"], s["tn"], s["fp"]))
    if baseline_path:
        b = report["baseline"]
        md += ["", "## Against the baseline", "", "Baseline: `%s`" % b["path"], "",
               "| Category | Baseline TP/FN/TN/FP | Now TP/FN/TN/FP | Baseline untestable | Now untestable |",
               "|---|---|---|---|---|"]
        for c, v in b["by_category"].items():
            f4 = lambda p: "%d/%d/%d/%d" % tuple(v.get(p + k, 0) for k in ("TP", "FN", "TN", "FP"))  # noqa: E731
            md.append("| %s | %s | %s | %d | %d |" % (c, f4("base_"), f4("now_"), v.get("base_untestable", 0),
                                                       v.get("now_untestable", 0)))
        md += ["", "%d case(s) changed:" % len(b["changes"]), ""]
        md += ["- %s: %s -> %s" % (x["test"], x["baseline"], x["now"]) for x in b["changes"]]
    if untestable:
        md += ["", "## Untestable", ""] + ["- %s: %s" % (u["test"], u["reason"]) for u in untestable]
    if meta["seed_failures"]:
        md += ["", "## Seed failures", ""] + ["- %s" % json.dumps(s) for s in meta["seed_failures"]]
    (out / "report.md").write_text("\n".join(md) + "\n")
    return "\n".join(md)


# --------------------------------------------------------------------------------------------------


def cdp_alive(ws):
    """A ws:// CDP endpoint answers /json/version on its host:port."""
    u = urllib.parse.urlsplit(ws)
    try:
        return get("http://%s/json/version" % u.netloc, 3)[0] == 200
    except Exception:
        return False


def resolve_dom(a):
    """(-dom value, note). The shared Chrome when one is named and answering, else a local one."""
    if a.no_dom:
        return "", ""
    remote = (a.dom_remote or os.environ.get("BURPSY_DOM_REMOTE", "")).strip()
    if remote.startswith("@"):
        try:
            remote = Path(remote[1:]).read_text().strip()
        except OSError:
            remote = ""
    note = ""
    if remote:
        if cdp_alive(remote):
            return remote, "shared Chrome %s" % remote
        note = "shared Chrome %s did not answer; " % remote
    local = local_chrome(a)
    return local, (note + "local Chrome %s" % local) if local else note


def local_chrome(a):
    if a.chrome:
        return a.chrome
    for c in (os.environ.get("BURPSY_CHROME"), shutil.which("chromium"), shutil.which("google-chrome"),
              shutil.which("google-chrome-stable"), os.path.expanduser("~/binc/chromium")):
        if c and os.path.exists(c) and os.access(c, os.X_OK):
            return c
    return ""


def make_ca(burpsy, ca, port):
    """Create the shared CA once, before any parallel start: N servers generating it at the same moment
    write a certificate and a key that do not match. burpsy writes it only under -intercept-tls, so
    this one start asks for that; the http-only workers then find it already there."""
    if (ca / "ca.key").exists() and (ca / "ca.crt").exists():
        return
    ca.mkdir(parents=True, exist_ok=True)
    p = PROCS.start("burpsy[ca]", [burpsy, "-proxy", "127.0.0.1:%d" % port, "-web", "127.0.0.1:%d" % (port + 1),
                                   "-intercept-tls", "-ca-dir", str(ca)], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        wait_until(lambda: (ca / "ca.key").exists() and (ca / "ca.crt").exists() and
                   API("http://127.0.0.1:%d" % (port + 1)).call("GET", "/api/stats", timeout=3) is not None,
                   60, "burpsy CA creation", p)
    finally:
        PROCS.stop(p)


def build_burpsy(out):
    dst = out / "burpsy"
    log("building burpsy from %s" % (REPO / "burpsy-go"))
    subprocess.check_call(["go", "build", "-o", str(dst), "./cmd/burpsy"], cwd=str(REPO / "burpsy-go"))
    return str(dst)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--jar", required=True, help="VulnerableApp jar (SasanLabs master 36d1090 for the committed list)")
    ap.add_argument("--out", required=True, help="output directory (report.json, report.md, chunks/, logs)")
    ap.add_argument("--burpsy", default="", help="burpsy binary; default: build this checkout's into --out, removed at the end")
    ap.add_argument("--requests", default=str(HERE / "vulnapp_requests.json"), help="the generated case list")
    ap.add_argument("--only", default="", help="comma-separated categories (test-id prefixes, e.g. JWTVulnerability)")
    ap.add_argument("--rows", default="",
                    help='comma-separated issue rows, named as findings name them (e.g. "Cross-site scripting (reflected)"): '
                         "run only the checks that can report them (only_rows); an unknown row fails the profile")
    ap.add_argument("--baseline", default="", help="a previous report.json, or score_va.py -raw.jsonl, to diff against")
    ap.add_argument("--app-port", type=int, default=9190)
    ap.add_argument("--app-host", default="localhost", help="host name the cases use (scope and XSS route match it)")
    ap.add_argument("--smtp-port", type=int, default=9125)
    ap.add_argument("--inbox-port", type=int, default=9126)
    ap.add_argument("--burpsy-base-port", type=int, default=19200, help="slot N uses this+2N (proxy) and +2N+1 (web)")
    ap.add_argument("--workers", "--parallel", dest="workers", type=int, default=8,
                    help="main-lane burpsy servers at once, each its own port pair (and local Chrome); cases are "
                         "I/O-bound, so more than the CPU count is fine")
    ap.add_argument("--timing-workers", type=int, default=2,
                    help="servers for the timing lane (blind SQLi, login rate limit, login-shaped categories)")
    ap.add_argument("--timing-lane", choices=("after", "alongside"), default="after",
                    help="run the timing lane after the main lane (default: no load skew) or alongside it")
    ap.add_argument("--chunk-size", type=int, default=4, help="cases per burpsy instance")
    ap.add_argument("--audit-timeout", type=int, default=600, help="seconds for one case's audit")
    ap.add_argument("--probe-timeout-ms", type=int, default=25000)
    ap.add_argument("--reseed-minutes", type=float, default=50, help="re-fetch a case's token when older than this")
    ap.add_argument("--no-dom", action="store_true", help="run without a DOM engine (DOM checks off, listed)")
    ap.add_argument("--dom-off-categories", default="",
                    help="categories audited WITHOUT the DOM engine (default: none). Not needed since "
                         "burpsy-react-ui-4kmr was fixed; kept to measure a category with and without the browser")
    ap.add_argument("--dom-remote", default="",
                    help="ws:// CDP endpoint of a shared Chrome, or @FILE holding one (default: $BURPSY_DOM_REMOTE)")
    ap.add_argument("--chrome", default="", help="browser binary for -dom when BURPSY_DOM_REMOTE is unset")
    ap.add_argument("--bchecks", default="", help="BCheck corpus directory, passed to burpsy -bchecks")
    ap.add_argument("--collaborator-server", default="",
                    help='passed to burpsy -collaborator-server ("public" or a server URL); without it OOB is SKIPPED')
    ap.add_argument("--collaborator-client", default="", help="passed to burpsy -collaborator-client (interactsh-client path); implies --collaborator-server public")
    ap.add_argument("--java-xmx", default="1g")
    ap.add_argument("--app-start-timeout", type=int, default=240)
    ap.add_argument("--app-console-log", default="", help="keep the app's WARN console output in this file")
    ap.add_argument("--va-parent", default="/tmp", help="parent of the app's run dir; its whole path must be traversable by uid 65534")
    ap.add_argument("--keep-va-dir", action="store_true", help="keep the app's run dir (uploads) for inspection")
    ap.add_argument("--run-as-current-user", action="store_true", help="non-root only: run the app as yourself")
    ap.add_argument("--allow-list-drift", action="store_true", help="score even when the list differs from the live app")
    a = ap.parse_args()
    # Trimmed and de-duplicated as the server does, so apply_profile's read-back compares like with like.
    a.rows = list(dict.fromkeys(r.strip() for r in a.rows.split(",") if r.strip()))
    if a.collaborator_client and not a.collaborator_server:
        # A client with no server named used to leave OOB SKIPPED, silently: interactsh-client's own
        # default is the public pool, so naming the client means "use it".
        a.collaborator_server = "public"

    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _on_signal)
    ports = [a.app_port, a.smtp_port, a.inbox_port] + [a.burpsy_base_port + i for i in
                                                        range(2 * (a.workers + a.timing_workers))]
    busy = [p for p in ports if port_in_use(p)]
    if busy:
        raise SystemExit("port(s) already in use: %s - this run starts its own instances and never reuses or "
                         "stops someone else's; pick other ports" % busy)
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    built = None
    va_dir = None
    try:
        burpsy = a.burpsy or build_burpsy(out)
        built = None if a.burpsy else burpsy
        start_mailsink(a, out)
        va_proc, va_dir = start_vulnapp(a, out)
        app_base = "http://%s:%d" % (a.app_host, a.app_port)

        reqs = rebase(json.load(open(a.requests)), app_base)
        missing, extra = check_list_matches_app(reqs, app_base)
        if (missing or extra) and not a.allow_list_drift:
            raise SystemExit("the case list does not match the live app (missing %d, extra %d): %s %s"
                             % (len(missing), len(extra), missing[:3], extra[:3]))
        only = [x for x in a.only.split(",") if x]
        sel = [r for r in reqs if not only or family(r["test"]) in only]
        if only and not sel:
            raise SystemExit("--only matched no case; categories are: %s" % sorted({family(r["test"]) for r in reqs}))
        seeded, identities, seed_fails = seed_all(sel, app_base, out)
        json.dump(seeded, open(out / "seeded-requests.json", "w"), indent=1)
        log("seeded %d case(s); %d reset identit(y/ies); %d seed failure(s)" % (len(seeded), len(identities), len(seed_fails)))

        dom, dom_note = resolve_dom(a)
        ability = abilities(a, dom, dom_note)
        not_set_up = []

        by_test = {r["test"]: r for r in seeded}
        order = sorted(by_test, key=lambda t: (any(x in HAZARD_TYPES for x in by_test[t]["vulnerabilityTypes"]), t))
        dom_off = {x for x in a.dom_off_categories.split(",") if x} if dom else set()
        dom_off &= {family(t) for t in order}
        if dom_off:
            not_set_up.append("%s run with %s OFF - %s" % (", ".join(sorted(dom_off)), " and ".join(DOM_SWITCHES),
                                                          DOM_SCOPED_OFF))
        timing = lambda t: (family(t) in TIMING_FAMILIES  # noqa: E731
                            or bool(TIMING_TYPES & set(by_test[t]["vulnerabilityTypes"])))
        # Chunks never mix lanes, nor DOM and non-DOM cases (the engine is a per-process flag).
        chunks = {"main": [], "timing": []}
        n = 0
        for lane in ("main", "timing"):
            for with_dom in ((True, False) if dom else (False,)):
                g = [t for t in order if timing(t) == (lane == "timing")
                     and (not dom or (family(t) not in dom_off) == with_dom)]
                for j in range(0, len(g), a.chunk_size):
                    chunks[lane].append(("c%04d" % n, g[j:j + a.chunk_size], with_dom, lane))
                    n += 1
        run = Run(a, out, burpsy, dom, by_test, app_base)
        run.identities = identities
        make_ca(burpsy, out / "ca", a.burpsy_base_port)
        log("%d case(s): main lane %d chunk(s) x %d workers, timing lane %d chunk(s) x %d workers (%s); DOM: %s"
            % (len(order), len(chunks["main"]), a.workers, len(chunks["timing"]), a.timing_workers, a.timing_lane,
               dom or "none"))
        t_run = time.time()
        exs = {"main": ThreadPoolExecutor(a.workers), "timing": ThreadPoolExecutor(a.timing_workers)}
        lane_secs = {}
        try:
            def lane_run(lane):
                t0 = time.time()
                futs = [exs[lane].submit(run.chunk, *c) for c in chunks[lane]]
                res = [f.result() for f in futs]
                lane_secs[lane] = round(time.time() - t0)
                return res
            if a.timing_lane == "alongside":
                drivers = ThreadPoolExecutor(2)
                fm, ft = drivers.submit(lane_run, "main"), drivers.submit(lane_run, "timing")
                results = fm.result() + ft.result()
                drivers.shutdown()
            else:
                results = lane_run("main") + lane_run("timing")
        finally:
            # On a signal: no new chunk starts, and the running ones see STOP and their burpsy die.
            STOP.set()
            for ex in exs.values():
                ex.shutdown(wait=False, cancel_futures=True)
        wall = {"cases_secs": round(time.time() - t_run), "lanes_secs": lane_secs}
        log("cases done in %ds (main %ss, timing %ss)" % (wall["cases_secs"], lane_secs.get("main"), lane_secs.get("timing")))
        app_uid = UNPRIV_UID if os.geteuid() == 0 else os.geteuid()
        if va_proc.poll() is not None:
            not_set_up.append("VulnerableApp exited during the run (rc %s)" % va_proc.returncode)
    except RuntimeError as e:  # a setup step that never became ready: a message, not a traceback
        raise SystemExit("full benchmark not run: %s" % e)
    finally:
        PROCS.stop_all()
        if va_dir and not a.keep_va_dir:
            shutil.rmtree(va_dir, ignore_errors=True)
        if built and os.path.exists(built):
            os.remove(built)

    adv = run.advisories or {}
    if not adv:
        not_set_up.append("advisory catalogue not read: findings scored by their own classifications only")
    profile = run.profile or {}
    rows, untestable = score(by_test, results, adv, order)
    meta = {
        "started": started, "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
        "burpsy": a.burpsy or ("built from %s" % subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                                                                 capture_output=True, text=True).stdout.strip()),
        "app": app_base, "app_uid": app_uid, "cases_in_list": len(reqs), "cases_selected": len(order), "only": only,
        "only_rows": a.rows,
        "dom": dom, "reset_test_identities": identities,
        "reset_mailbox_url": profile.get("reset_mailbox_url", ""),
        "checks_on": sorted(k for k, v in profile.items() if k.startswith("check_") and v is True),
        "checks_off": sorted(k for k, v in profile.items() if k.startswith("check_") and v is False),
        "xss_browser_targets": profile.get("xss_browser_targets"),
        "not_set_up": not_set_up, "seed_failures": seed_fails,
        "wall_time": wall, "workers": a.workers, "timing_workers": a.timing_workers, "timing_lane": a.timing_lane,
        "abilities": [{"ability": n, "status": st, "detail": d} for n, st, d in ability],
        "list_drift": {"missing": missing, "extra": extra},
    }
    print(write_report(out, meta, rows, untestable, adv, a.baseline))
    log("report: %s/report.md and report.json" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
