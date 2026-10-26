#!/usr/bin/env python3
"""Run the non-charging PayPal check under the worker's Unix identity."""
import subprocess

from bootstrap import PYTHON, ROOT, assert_sandbox, environment

assert_sandbox()
subprocess.run(["runuser", "-u", "xportal_worker", "--", PYTHON, "manage.py", "paypal_check"],
               cwd=ROOT, env=environment("worker"), check=True)
