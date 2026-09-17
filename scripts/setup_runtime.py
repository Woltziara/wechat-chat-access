#!/usr/bin/env python3
"""Install a private local reader runtime; never access WeChat data or keys."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--with-capture", action="store_true")
    args = ap.parse_args()
    base = Path.home() / "Library/Application Support/CodexWeChatRead"
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    runtime = base / "runtime"
    python = runtime / "bin/python"
    uv = shutil.which("uv")
    if not python.exists():
        command = ([uv, "venv", str(runtime), "--python", sys.executable]
                   if uv else [sys.executable, "-m", "venv", str(runtime)])
        subprocess.run(command, check=True, stdout=sys.stderr)
    packages = ["sqlcipher3==0.6.2", "zstandard==0.25.0"]
    if args.with_capture:
        packages.append("frida==17.18.0")
    command = ([uv, "pip", "install", "--python", str(python), *packages]
               if uv else [str(python), "-m", "pip", "install", *packages])
    subprocess.run(command, check=True, stdout=sys.stderr)
    probe = "import sqlcipher3,zstandard,json; c=sqlcipher3.connect(':memory:'); print(json.dumps({'cipher':c.execute('PRAGMA cipher_version').fetchone()[0],'zstd':zstandard.__version__})); c.close()"
    result = subprocess.run([str(python), "-c", probe], check=True,
                            capture_output=True, text=True)
    print(json.dumps({"status": "ready", "python": str(python),
                      "capture_requested": args.with_capture,
                      "dependencies": json.loads(result.stdout)}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"status": "error", "error_code": "runtime_setup_failed"}))
        sys.exit(1)
