#!/usr/bin/env python3
"""Mechanical loopback boundary for live parity reference runs (parity-lane policy, 2026-10-25).

Payload hygiene is defence-in-depth, never the guarantee (W12's j1mk.16 finding: a literal
host rewrite misses percent-encoded external hosts). The guarantee here is a bubblewrap
network namespace with no external interface: `bwrap --unshare-net` gives the run a private
loopback-only namespace, so a redirect-following tool CANNOT reach an off-box host no matter
what a payload decodes to.

cmd_run wraps the whole fixture stack (demo-target, burpsy, parity_run) in one namespace so
they can still see each other on 127.0.0.1. The preflight proves the boundary before any tool
starts: an external connect must fail AND a loopback roundtrip must work. The payload audit
(layer 2) enumerates host tokens in every payloads file the run can touch, in raw, once- and
twice-percent-decoded and literal \\xNN forms, and is written next to the run's artifacts.
"""
import json, os, re, socket, subprocess, sys, threading, urllib.parse
from pathlib import Path

BWRAP = ["bwrap", "--unshare-net", "--dev-bind", "/", "/"]
INSIDE_ENV = "PARITY_NETBOUND_INSIDE"


def host_tokens(payload):
    """Host tokens a payload names in any decoded form (raw, 1-2x percent-decode, \\xNN)."""
    forms = {payload}
    d1 = urllib.parse.unquote(payload, errors="replace")
    forms.add(d1)
    forms.add(urllib.parse.unquote(d1, errors="replace"))
    forms.add(re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), payload))
    # browsers normalize backslashes to slashes; a host behind a \ is still a host
    forms |= {f.replace("\\", "/") for f in list(forms)}
    hosts = set()
    for f in forms:
        for tok in re.findall(r"(?:@|//|:)([A-Za-z0-9.\[\]:_-]+)", f):
            tok = tok.split("@")[-1]               # userinfo
            tok = re.sub(r":\d+$", "", tok)       # trailing :port
            tok = tok.strip("[]").strip(".").lower()
            if tok and re.search(r"[a-z]|\d{3}", tok):
                if tok.isdigit() and int(tok) <= 65535:
                    continue  # a port captured via the ':' prefix, not a dword host
                hosts.add(tok)
        # bare numeric IP forms (dword/octal/hex), excluding :port positions
        for h in re.findall(r"(?<![:\w.])(0x[0-9a-f]+|\d{3,}(?:\.\d+)*|\d+\.\d+\.\d+\.\d+)(?![\w.])", f):
            hosts.add(h.lower())
    return hosts


def audit_payloads(path):
    """Per-line host audit of one payloads file; external = not 127.0.0.1/localhost."""
    lines = [l for l in Path(path).read_text().splitlines() if l.strip()]
    rows = []
    for p in lines:
        hosts = sorted(host_tokens(p))
        rows.append({"payload": p, "hosts": hosts,
                     "external": [h for h in hosts
                                  if not (h.startswith("127.0.0.1") or h == "localhost")]})
    return {"file": str(path), "lines": len(lines),
            "lines_with_external_hosts": sum(1 for r in rows if r["external"]), "rows": rows}


def boundary_identity():
    """Facts about the namespace the caller is IN, recorded verbatim. Nothing here assumes
    /proc/1, a host, or 'loopback only': the caller compares the captured value against a
    baseline it captured OUTSIDE the boundary before launch and reads the interface list."""
    return {
        "net_ns": os.readlink("/proc/self/ns/net"),
        "pid_ns": os.readlink("/proc/self/ns/pid"),
        "interfaces": sorted(os.listdir("/sys/class/net")),
    }


def preflight(external_probe=("1.1.1.1", 443), timeout=3):
    """The boundary contract: external MUST fail, loopback MUST work. Raises on any doubt."""
    try:
        socket.create_connection(external_probe, timeout=timeout).close()
        raise RuntimeError("boundary broken: external connect %s succeeded" % (external_probe,))
    except RuntimeError:
        raise
    except OSError:
        pass  # unreachable/refused: expected inside the boundary
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got = []

    def accept():
        c, _ = srv.accept()
        got.append(c.recv(8))
        c.close()

    t = threading.Thread(target=accept, daemon=True)
    t.start()
    socket.create_connection(("127.0.0.1", srv.getsockname()[1]), timeout=timeout).sendall(b"probe")
    t.join(timeout)
    srv.close()
    if got != [b"probe"]:
        raise RuntimeError("boundary broken: loopback roundtrip failed")
    return True


def cmd_preflight():
    preflight()
    print("net boundary preflight OK: external connect refused, loopback roundtrip works")


def cmd_audit(path):
    print(json.dumps(audit_payloads(path), indent=1))


def cmd_run(argv, audit_out=None, receipt_path=None):
    """Re-exec argv inside the boundary (once), preflight first; record receipts after.

    The receipt binds the boundary to THIS run: the inner namespace identity must differ
    from the outer baseline the driver captured before launch (PARITY_NETBOUND_OUTER_NS),
    and the interface list is recorded verbatim - no unexamined loopback-only claim. The
    payload audit covers the payloads files actually fed (the parity out dir)."""
    if not os.environ.get(INSIDE_ENV):
        return subprocess.call(BWRAP + ["env", "%s=1" % INSIDE_ENV] + argv)
    preflight()
    identity = boundary_identity()
    outer = os.environ.get("PARITY_NETBOUND_OUTER_NS")
    identity["outer_net_ns_baseline"] = outer
    identity["namespace_differs_from_outer"] = (outer is not None and identity["net_ns"] != outer)
    try:
        return subprocess.call(argv)
    finally:
        if receipt_path:
            Path(receipt_path).write_text(json.dumps(identity, indent=1))
        if audit_out:
            audits = [audit_payloads(p) for p in sorted(Path(audit_out[0]).rglob("payloads.txt"))]
            Path(audit_out[1]).write_text(json.dumps(audits, indent=1))



def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd, rest = argv[1], argv[2:]
    if cmd == "preflight":
        cmd_preflight()
        return 0
    if cmd == "audit" and rest:
        cmd_audit(rest[0])
        return 0
    if cmd == "run" and rest:
        return cmd_run(rest)
    if cmd == "run-audit" and len(rest) >= 4:
        # run-audit AUDIT_ROOT AUDIT_JSON RECEIPT_JSON -- CMD...
        audit_root, audit_json, receipt, cmdv = rest[0], rest[1], rest[2], rest[4:]
        return cmd_run(cmdv, audit_out=(audit_root, audit_json), receipt_path=receipt)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
