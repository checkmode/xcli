"""Sandbox-only settings; public processes never receive merchant credentials."""
import re
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured


def configuration(env, role):
    enabled = env.get("PORTAL_PAYPAL_ENABLED", "0") == "1"
    if env.get("PORTAL_PAYPAL_ENVIRONMENT", "sandbox") != "sandbox":
        raise ImproperlyConfigured("Only the PayPal Sandbox environment is supported")
    origin = env.get("PORTAL_PUBLIC_ORIGIN", "http://127.0.0.1:18088")
    try:
        url = urlsplit(origin)
        port = url.port
        local = url.hostname in {"localhost", "127.0.0.1", "::1"}
        if (url.scheme not in {"http", "https"} or (url.scheme == "http" and not local)
                or not url.hostname or url.username is not None or url.password is not None
                or url.path or url.query or url.fragment or (port is not None and not 1 <= port <= 65535)
                or any(c.isspace() for c in origin) or "\\" in origin):
            raise ValueError()
    except ValueError as exc:
        raise ImproperlyConfigured("PORTAL_PUBLIC_ORIGIN requires an HTTPS origin, or an HTTP loopback origin") from exc
    trusted = role in {"worker", "hooks", "owner"}
    result = {"PAYPAL_ENABLED": enabled, "PUBLIC_ORIGIN": origin,
              "PAYPAL_CLIENT_ID": "", "PAYPAL_CLIENT_SECRET": "", "PAYPAL_MERCHANT_ID": "", "PAYPAL_WEBHOOK_ID": ""}
    if enabled and trusted:
        for name in ("CLIENT_ID", "CLIENT_SECRET", "MERCHANT_ID", "WEBHOOK_ID"):
            result["PAYPAL_" + name] = env.get("PORTAL_PAYPAL_" + name, "")
        if any(not result["PAYPAL_" + key] for key in ("CLIENT_ID", "CLIENT_SECRET", "MERCHANT_ID")):
            raise ImproperlyConfigured("PayPal Sandbox requires Client ID, Client Secret, and merchant ID in trusted processes")
        if not re.fullmatch(r"[A-Z0-9]{5,32}", result["PAYPAL_MERCHANT_ID"]):
            raise ImproperlyConfigured("Invalid PayPal Sandbox merchant ID")
    return result
