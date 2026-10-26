"""Read optional private Sandbox credentials before dropping service privileges."""
import json
import os
import stat


def paypal_environment(role, environ=None):
    environ = os.environ if environ is None else environ
    values = {}
    config_path = environ.get("PORTAL_PAYPAL_CONFIG")
    if config_path:
        fd = os.open(config_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("PayPal config must be a private regular file (mode 0600 or 0400)")
            raw = handle.read(16385)
            if len(raw) > 16384:
                raise ValueError("PayPal config is too large")
            try:
                values = json.loads(raw)
                if not isinstance(values, dict) or any(not isinstance(v, str) for v in values.values()):
                    raise ValueError()
            except (ValueError, TypeError):
                raise ValueError("PayPal config must be a JSON object containing string values") from None
    def value(name, default=""):
        return values.get(name, environ.get(name, default))
    result = {"PORTAL_PAYPAL_ENABLED": value("PORTAL_PAYPAL_ENABLED", "0"),
              "PORTAL_PAYPAL_ENVIRONMENT": value("PORTAL_PAYPAL_ENVIRONMENT", "sandbox"),
              "PORTAL_PUBLIC_ORIGIN": value("PORTAL_PUBLIC_ORIGIN", "http://127.0.0.1:18088")}
    if role in {"worker", "hooks", "owner"}:
        for name in ("CLIENT_ID", "CLIENT_SECRET", "MERCHANT_ID", "WEBHOOK_ID"):
            key = "PORTAL_PAYPAL_" + name
            result[key] = value(key)
    return result
