#!/usr/bin/env python3
"""Run tests against a disposable PostgreSQL test DB and temporary gateway directories."""
import os
import subprocess

from bootstrap import PYTHON, ROOT, assert_sandbox, environment

assert_sandbox()
binary = os.environ.get("XG_TEST_BINARY", "/tmp/xcli-build-check/xray-gateway-panel")
env = environment("owner", "postgres")
env.update(XG_TEST_BINARY=binary, XG_LEGACY_APP="/workspace/app.py")
subprocess.run(["runuser", "-u", "postgres", "--", PYTHON, "manage.py", "test", "commerce", "--noinput", "--verbosity", "2"], cwd=ROOT, env=env, check=True)
subprocess.run([PYTHON, "-m", "pytest", "-q", "cpp/tests/test_http.py", "cpp/tests/test_features.py", "tests/test_app.py"], cwd="/workspace", env=env, check=True)
