#!/usr/bin/env python3
import os
import pathlib
import signal
import socket
import subprocess
import time

from bootstrap import PYTHON, ROOT, STATE, assert_sandbox, environment

assert_sandbox()
binary = os.environ.get("XG_TEST_BINARY", "/tmp/xcli-build-check/xray-gateway-panel")
children = []
stopping = False


def stop(*_):
    global stopping
    stopping = True


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
services = [
    ("gateway", "xgateway", [binary, "--state", str(STATE / "gateway"), "--settings", str(STATE / "gateway/settings.json"), "--static", "/workspace/static", "--port", "18080", "--offline", "--no-auto-backup", "--provision-socket", "/run/xportal-bridge/provision.sock", "--provision-uid", "1500"], {}),
    ("hooks", "xportal_worker", ["/opt/portal-venv/bin/gunicorn", "config.wsgi:application", "--bind", "127.0.0.1:8089", "--workers", "2", "--threads", "4", "--timeout", "20", "--no-control-socket"], environment("hooks")),
    ("worker", "xportal_worker", [PYTHON, "manage.py", "portal_worker"], environment("worker")),
    ("web", "xportal_web", ["/opt/portal-venv/bin/gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8088", "--workers", "2", "--threads", "4", "--timeout", "20", "--no-control-socket"], environment("web")),
]
try:
    for name, user, command, env in services:
        log = (STATE / "logs" / f"{name}.log").open("ab", buffering=0)
        child = subprocess.Popen(["runuser", "-u", user, "--", *command], cwd=ROOT, env=env or {"PATH": os.environ["PATH"]}, stdout=log, stderr=log, start_new_session=True)
        children.append((child, log))
    for _ in range(100):
        if any(child.poll() is not None for child, _ in children):
            raise RuntimeError("A sandbox service failed; inspect /sandbox/logs inside this container")
        try:
            with socket.create_connection(("127.0.0.1", 8088), timeout=.2):
                break
        except OSError:
            time.sleep(.1)
    else:
        raise RuntimeError("Sandbox web listener did not become ready")
    print("Local sandbox ready on port 8088; gateway, worker, hooks, and web use separate processes.", flush=True)
    while not stopping:
        if any(child.poll() is not None for child, _ in children):
            raise RuntimeError("A sandbox service exited; inspect /sandbox/logs")
        time.sleep(.5)
finally:
    for child, _ in children:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
    for child, log in children:
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        log.close()
