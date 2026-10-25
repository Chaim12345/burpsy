#!/usr/bin/env python3
"""Pinned, hash-checked reference tools for the parity harness (j1mk.1).

Same discipline as scripts/ci-install-tools.sh: every tool is a pinned archive at a pinned URL
with a pinned SHA-256, the archive is re-checked on every install, and a stamp holding the hash
makes an already-correct install a no-op. A tool whose archive does not match its pin is refused,
loudly — a parity run against "some version, probably" is not evidence.

The `note` field records each tool's maintenance status as checked when the pin was made (the
bead's "verify each tool is still maintained when its bead starts" step). Update it with the pin.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

TOOLS = {
    # Arjun — hidden parameter discovery (j1mk.13). Last release 2.2.7 (2024-11-03); the repo's
    # last push was 2025-02, checked 2026-10-25: quiet but not archived. Pinned to the release
    # tag's commit. The codeload tarball hash is for GitHub's archive of that commit, measured
    # 2026-10-25; a changed hash means GitHub re-rolled the archive and the pin must be re-seen.
    "arjun": {
        "name": "arjun", "version": "2.2.7", "kind": "pip-tarball",
        "url": "https://codeload.github.com/s0md3v/Arjun/tar.gz/1b11c3574e1e173b47990e7d914f0c183986ec32",
        "sha256": "751e3717779a3258f49d84b7ed19081ac2cb4e34fe35cfccc04995ba5afa49be",
        "note": "maintained: last release 2024-11-03, last push 2025-02 (checked 2026-10-25)",
    },
    # Corsy — CORS misconfiguration (j1mk.14). Release 1.0-rc (2021-01-28); last push 2022-09,
    # checked 2026-10-25: unmaintained, but it is the class's named reference tool (the bead
    # names it) and its checks are still the canonical list. Pinned to the release tag's commit.
    "corsy": {
        "name": "corsy", "version": "1.0-rc", "kind": "script-tarball",
        "url": "https://codeload.github.com/s0md3v/Corsy/tar.gz/06f4d4a06d6a8ed33acfcb739a8fbb4393522f09",
        "sha256": "2ca0ef9b46dc87fcb87d2f6d32d6e888f080a784ba4512db69c098b322055b5b",
        "entry": "corsy.py",
        "pip_requires": ["requests"],
        "note": "UNMAINTAINED since 2022-09 (checked 2026-10-25); kept as the named reference",
    },
    # crlfuzz — CRLF / header injection (j1mk.15). Release v1.4.1 (2021-04-03), but the repo was
    # pushed to as recently as 2026-10, checked 2026-10-25. The pinned hash is the release's own
    # published checksums.txt value, not one we measured.
    "crlfuzz": {
        "name": "crlfuzz", "version": "v1.4.1", "kind": "tarball-binary",
        "url": "https://github.com/dwisiswant0/crlfuzz/releases/download/v1.4.1/crlfuzz_1.4.1_linux_amd64.tar.gz",
        "sha256": "033e97108f1ead4dbd810843316ca3eb9e7be48bb27e058010bd3d919a0a6235",
        "path_in_archive": "crlfuzz",
        "note": "release 2021-04-03; repo still pushed 2026-10 (checked 2026-10-25)",
    },
}


class HashMismatch(Exception):
    pass


def _fetch(url, dest):
    with urllib.request.urlopen(url, timeout=120) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_tool(pin, tools_dir, fetcher=None):
    """Install one pinned tool under tools_dir and describe how to run it.

    Returns a dict: {"name", "version", "stamp", "dir"} plus kind-specific run fields:
    "binary" for a tarball-binary, "venv_bin" for a pip-tarball, "script" + "venv_bin" for a
    script-tarball. Re-checks the archive's hash on every install; a stamped install whose stamp
    matches the pin is not fetched again. fetcher(url, dest) is injectable for tests.
    """
    fetcher = fetcher or _fetch
    tools_dir = Path(tools_dir)
    tdir = tools_dir / pin["name"]
    stamp = tdir / ".stamp"
    want = {"version": pin["version"], "sha256": pin["sha256"]}
    if stamp.exists() and json.loads(stamp.read_text()) == want and _installed_files(pin, tdir):
        return _describe(pin, tdir, stamp)
    tdir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=tools_dir) as tmp:
        archive = Path(tmp) / "tool.tar.gz"
        fetcher(pin["url"], archive)
        got = _sha256(archive)
        if got != pin["sha256"]:
            raise HashMismatch(
                f"{pin['name']}: archive sha256 {got} != pinned {pin['sha256']} ({pin['url']})")
        _install(pin, archive, tdir)
    stamp.write_text(json.dumps(want))
    return _describe(pin, tdir, stamp)


def _installed_files(pin, tdir):
    d = _describe(pin, tdir, tdir / ".stamp")
    for key in ("binary", "script", "venv_bin"):
        if key in d and not Path(d[key]).exists():
            return False
    return any(k in d for k in ("binary", "script", "venv_bin"))


def _describe(pin, tdir, stamp):
    out = {"name": pin["name"], "version": pin["version"], "stamp": str(stamp), "dir": str(tdir)}
    if pin["kind"] == "tarball-binary":
        out["binary"] = str(tdir / pin["path_in_archive"])
    elif pin["kind"] == "script-tarball":
        out["script"] = str(tdir / "src" / pin["entry"])
        out["venv_bin"] = str(tdir / "venv" / "bin")
    elif pin["kind"] == "pip-tarball":
        out["venv_bin"] = str(tdir / "venv" / "bin")
    return out


def _install(pin, archive, tdir):
    if pin["kind"] == "tarball-binary":
        with tarfile.open(archive) as tf:
            tf.extractall(tdir, filter="data")
        os.chmod(Path(tdir) / pin["path_in_archive"], 0o755)
    elif pin["kind"] == "script-tarball":
        src = Path(tdir) / "src"
        src.mkdir(exist_ok=True)
        with tarfile.open(archive) as tf:
            tf.extractall(src, filter="data")
        # codeload tarballs nest everything under one <repo>-<sha>/ directory.
        subs = [p for p in src.iterdir() if p.is_dir()]
        if len(subs) == 1:
            for p in list(subs[0].iterdir()):
                shutil.move(str(p), src)
            subs[0].rmdir()
        _venv(tdir, pin.get("pip_requires", []))
    elif pin["kind"] == "pip-tarball":
        _venv(tdir, [])
        pip = str(Path(tdir) / "venv" / "bin" / "pip")
        subprocess.run([pip, "install", "--quiet", str(archive)], check=True)


def _venv(tdir, requirements):
    venv = Path(tdir) / "venv"
    if not (venv / "bin" / "python").exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    if requirements:
        subprocess.run([str(venv / "bin" / "pip"), "install", "--quiet", *requirements], check=True)
