#!/usr/bin/env python3
"""Exercise the live sandbox HTTP and Unix-user boundaries, without exposing secrets."""
import http.cookiejar
import json
import os
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from bootstrap import PYTHON, STATE, assert_sandbox

assert_sandbox()
BASE = "http://127.0.0.1:8088"


class Browser:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.cookies))

    def get(self, path):
        with self.opener.open(BASE + path, timeout=10) as response:
            return response.read().decode(), urllib.parse.urlsplit(response.url).path

    def post(self, path, fields):
        csrf = next(cookie.value for cookie in self.cookies if cookie.name == "xportal_csrf")
        values = {**fields, "csrfmiddlewaretoken": csrf}
        request = urllib.request.Request(BASE + path, urllib.parse.urlencode(values).encode(), {"Origin": BASE}, method="POST")
        with self.opener.open(request, timeout=10) as response:
            return response.read().decode(), urllib.parse.urlsplit(response.url).path


browser = Browser()
username = "sandbox-demo-" + uuid.uuid4().hex[:8]
password = secrets.token_urlsafe(24)
browser.get("/signup/")
page, path = browser.post("/signup/", {"username": username, "password1": password, "password2": password})
assert path == "/account/", "Live signup failed"
for channel in ("card", "paypal", "wechat", "alipay"):
    page, _ = browser.get("/account/")
    nonce = re.search(r'name="nonce" value="([^"]+)"', page).group(1)
    _, order_path = browser.post("/checkout/", {"nonce": nonce, "plan": "sandbox-30-days", "amount_minor": "1"})
    for _ in range(80):
        page, _ = browser.get(order_path)
        if "模拟付款成功" in page:
            break
        time.sleep(.1)
    else:
        raise AssertionError("Checkout did not become payable")
    assert "1.00 USD" in page, "Public client changed trusted order price"
    browser.post(order_path + "sandbox-pay/", {"channel": channel})
    for _ in range(100):
        page, _ = browser.get(order_path)
        if "沙箱权限已创建" in page:
            break
        time.sleep(.1)
    else:
        raise AssertionError("Verified sandbox payment did not complete provisioning")
    other = Browser()
    # An anonymous visitor must be redirected to login, never receive the order.
    _, location = other.get(order_path)
    assert location == "/login/"

# OS boundary: the public web UID cannot traverse the bridge directory or read controller data.
for target in ("/run/xportal-bridge/provision.sock", "/sandbox/gateway/gateway.sqlite", "/sandbox/config.json"):
    probe = subprocess.run(["runuser", "-u", "xportal_web", "--", PYTHON, "-c",
        "import os,sys; sys.exit(1 if os.access(sys.argv[1],os.R_OK) or os.access(sys.argv[1],os.W_OK) else 0)", target])
    assert probe.returncode == 0, "Public UID can access a protected resource"

# Even root can open the filesystem socket but fails SO_PEERCRED: only the configured worker UID is accepted.
probe = subprocess.run([PYTHON, "-c", "import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect('/run/xportal-bridge/provision.sock'); s.sendall(b'{}\\n');\ntry: data=s.recv(1024)\nexcept ConnectionResetError: data=b''\nassert not data"], capture_output=True)
assert probe.returncode == 0, "Peer UID restriction was not enforced"

# PostgreSQL enforces the same boundary on an actual connection owned by the public Unix user.
sql = "SELECT has_table_privilege(current_user,'commerce_payment','INSERT'), has_table_privilege(current_user,'commerce_provisionjob','INSERT'), has_table_privilege(current_user,'commerce_order','UPDATE'), has_table_privilege(current_user,'commerce_plan','UPDATE');"
result = subprocess.run(["runuser", "-u", "xportal_web", "--", "psql", "-d", "xportal_sandbox", "-Atc", sql], check=True, capture_output=True, text=True)
assert result.stdout.strip() == "f|f|f|f", "Public database role can write trusted state"

credentials = STATE / "demo-login.json"
fd = os.open(credentials, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as handle:
    json.dump({"username": username, "password": password, "order_path": order_path}, handle)
print(json.dumps({"signup": "passed", "channels": ["card", "paypal", "wechat", "alipay"], "renewals": 3,
    "public_database_boundary": "passed", "public_filesystem_boundary": "passed", "peer_uid_boundary": "passed",
    "gateway_mode": "isolated_offline", "demo_credentials": "private container file"}))
