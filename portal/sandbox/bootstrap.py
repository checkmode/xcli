#!/usr/bin/env python3
"""Initialize a disposable LOCAL Linux container. Never run on the production host."""
import json
import os
import pathlib
import pwd
import secrets
import subprocess

ROOT = pathlib.Path("/workspace/portal")
STATE = pathlib.Path("/sandbox")
PYTHON = "/opt/portal-venv/bin/python"


def run(argv, **kwargs):
    kwargs.setdefault("check", True)
    return subprocess.run(argv, **kwargs)


def assert_sandbox():
    if os.geteuid() != 0 or not pathlib.Path("/run/.xcli-portal-sandbox").is_file() or not ROOT.is_dir():
        raise SystemExit("Requires the marked local sandbox container")
    if pathlib.Path("/etc/xray-gateway/settings.json").exists():
        raise SystemExit("Refusing to initialize a container containing an existing gateway deployment")


def config():
    return json.loads((STATE / "config.json").read_text())


def environment(role, db_user=None):
    value = config()
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PORTAL_SANDBOX": "1", "PORTAL_ROLE": role,
           "PORTAL_SECRET_KEY": value["secret"], "PORTAL_DB_USER": db_user or ("xportal_worker" if role in {"worker", "hooks"} else "xportal_" + role),
           "PORTAL_DB_NAME": "xportal_sandbox", "PORTAL_PROVISION_SOCKET": "/run/xportal-bridge/provision.sock"}
    env.pop("PORTAL_SANDBOX_SIGNING_KEY", None)
    if role in {"worker", "hooks", "owner"}:
        env["PORTAL_SANDBOX_SIGNING_KEY"] = value["payment_key"]
    return env


def initialize():
    assert_sandbox()
    STATE.mkdir(mode=0o755, exist_ok=True)
    for name, uid in (("xportal_worker", 1500), ("xgateway", 1501), ("xportal_web", 1502), ("xportal_owner", 1503)):
        try:
            if pwd.getpwnam(name).pw_uid != uid:
                raise SystemExit("Sandbox user identity mismatch")
        except KeyError:
            run(["useradd", "--uid", str(uid), "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", name])
    run(["usermod", "-a", "-G", "xportal_worker", "xgateway"])
    if not (STATE / "config.json").exists():
        fd = os.open(STATE / "config.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"secret": secrets.token_urlsafe(48), "payment_key": secrets.token_urlsafe(48)}, handle)
    for directory, uid, gid, mode in ((STATE / "gateway", 1501, 1501, 0o700), (pathlib.Path("/run/xportal-bridge"), 1501, 1500, 0o2750), (STATE / "logs", 0, 0, 0o700)):
        directory.mkdir(exist_ok=True)
        os.chown(directory, uid, gid)
        directory.chmod(mode)
    settings = STATE / "gateway" / "settings.json"
    if not settings.exists():
        settings.write_text(json.dumps({"domain": "sandbox.invalid", "public_ip": "192.0.2.1", "origin": "https://sandbox.invalid", "admin_origin": "https://admin.sandbox.invalid",
            "reality_sni": "example.com", "reality_public": "p" * 43, "short_id": "aabbccdd", "ws_path": "/connect/sandbox"}))
        os.chown(settings, 1501, 1501)
        settings.chmod(0o600)
    if run(["pg_ctlcluster", "18", "main", "status"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode:
        run(["pg_ctlcluster", "18", "main", "start"])
    for role in ("xportal_web", "xportal_worker", "xportal_owner"):
        exists = run(["runuser", "-u", "postgres", "--", "psql", "-Atc", f"SELECT 1 FROM pg_roles WHERE rolname='{role}'"], capture_output=True, text=True).stdout.strip()
        if not exists:
            run(["runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-c", f"CREATE ROLE {role} LOGIN"])
    exists = run(["runuser", "-u", "postgres", "--", "psql", "-Atc", "SELECT 1 FROM pg_database WHERE datname='xportal_sandbox'"], capture_output=True, text=True).stdout.strip()
    if not exists:
        run(["runuser", "-u", "postgres", "--", "createdb", "--owner=xportal_owner", "xportal_sandbox"])
    for command in ("migrate", "portal_setup"):
        run(["runuser", "-u", "xportal_owner", "--", PYTHON, "manage.py", command, "--noinput"] if command == "migrate" else
            ["runuser", "-u", "xportal_owner", "--", PYTHON, "manage.py", command], cwd=ROOT, env=environment("owner"))
    print("Local sandbox database, Unix identities, and private gateway state are ready.")


if __name__ == "__main__":
    initialize()
