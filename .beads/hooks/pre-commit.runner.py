#!/usr/bin/env python3
"""The mcp-agent-mail chain-runner for pre-commit (burpsy-react-ui-5r80).

This is the body the pre-commit hook used to carry inline. It moved to its own file so the hook can
be sh — the language bd's integration appends its block in — and is invoked by the hook before bd's
section runs, so the chain behaviour is preserved exactly: every executable in hooks.d/pre-commit
runs in name order, then pre-commit.orig if it exists, and the first nonzero exit is the hook's exit.

The runner had never run in this repository: the file it lived in did not parse (a shell block
appended after this module's sys.exit), so every child hook and the bd block were dead code that a
push only reached by --no-verify. Moving it out does not change what it does — it changes who can
call it.
"""
import os
import sys
import stat
import subprocess
from pathlib import Path

# The chain-runner's own directory: hooks.d sits beside it, and the .orig convention is unchanged.
HOOK_DIR = Path(__file__).parent
RUN_DIR = HOOK_DIR / 'hooks.d' / 'pre-commit'
ORIG = HOOK_DIR / 'pre-commit.orig'


def _is_exec(p: Path) -> bool:
    try:
        st = p.stat()
        return bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except Exception:
        return False


def _list_execs() -> list[Path]:
    if not RUN_DIR.exists() or not RUN_DIR.is_dir():
        return []
    items = sorted([p for p in RUN_DIR.iterdir() if p.is_file()], key=lambda p: p.name)
    # On POSIX, honor exec bit; on Windows, include all files (we'll dispatch .py via python).
    if os.name == 'posix':
        try:
            items = [p for p in items if _is_exec(p)]
        except Exception:
            pass
    return items


def _run_child(path: Path, *, stdin_bytes=None):
    # On Windows, prefer 'python' for .py plugins to avoid PATHEXT reliance.
    try:
        if os.name != 'posix' and path.suffix.lower() == '.py':
            return subprocess.run([sys.executable, str(path)], input=stdin_bytes, check=False).returncode
        return subprocess.run([str(path)], input=stdin_bytes, check=False).returncode
    except OSError as exc:
        print(f'mcp-agent-mail chain-runner: could not execute {path.name}: {exc}', file=sys.stderr)
        return 126


def _remember_failure(path: Path, rc: int, first_failure: int) -> int:
    if rc == 0:
        return first_failure
    print(f'mcp-agent-mail chain-runner: {path.name} exited with status {rc}', file=sys.stderr)
    return first_failure or rc


def main() -> int:
    first_failure = 0
    for exe in _list_execs():
        rc = _run_child(exe)
        first_failure = _remember_failure(exe, rc, first_failure)

    if ORIG.exists():
        rc = _run_child(ORIG)
        first_failure = _remember_failure(ORIG, rc, first_failure)
    return first_failure


if __name__ == '__main__':
    sys.exit(main())
