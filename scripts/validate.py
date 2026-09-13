#!/usr/bin/env python3
"""Offline validation entry point; uses pytest when present, unittest otherwise."""
from __future__ import annotations
import pathlib
import py_compile
import shutil
import subprocess
import sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
def main() -> int:
    errors = []
    for source in sorted((ROOT / "realitygate").glob("*.py")):
        try:
            py_compile.compile(str(source), doraise=True)
        except py_compile.PyCompileError as exc:
            errors.append(str(exc))
    if errors:
        print("Python compile check failed:")
        print("\n".join(errors))
        return 1
    pytest = shutil.which("pytest")
    if pytest:
        command = [pytest, "-q"]
    else:
        print("pytest not installed; using stdlib unittest fallback")
        command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", str(ROOT), "-v"]
    return subprocess.call(command, cwd=ROOT)
if __name__ == "__main__":
    raise SystemExit(main())
