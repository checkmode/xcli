#!/usr/bin/env python3
import os
import pathlib
import subprocess
import sys

from bootstrap import PYTHON, ROOT, initialize

# This entrypoint is packaged only in the disposable development container.
pathlib.Path("/run/.xcli-portal-sandbox").touch(mode=0o600)
initialize()
if len(sys.argv) > 1:
    if sys.argv[1:] != ["test"]:
        raise SystemExit("Only the optional 'test' mode is supported")
    subprocess.run(["ctest", "--test-dir", "/tmp/xcli-build-check", "--output-on-failure"], check=True)
    os.execv(PYTHON, [PYTHON, str(ROOT / "sandbox/check.py")])
os.execv(PYTHON, [PYTHON, str(ROOT / "sandbox/serve.py")])
