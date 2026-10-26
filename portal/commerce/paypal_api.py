"""Small, bounded Orders v2 client. The destination is always PayPal Sandbox."""
import base64
import hashlib
import json
import re
import threading
import time
import urllib.error
import urllib.request

from django.conf import settings

API_ORIGIN = "https://api-m.sandbox.paypal.com"
MAX_RESPONSE = 256 * 1024


class APIError(Exception):
    def __init__(self, status=0, code="UNAVAILABLE"):
        self.status = status
        self.code = code if re.fullmatch(r"[A-Z0-9_]{1,64}", code) else "API_ERROR"
        super().__init__(f"PayPal:{self.status}:{self.code}")


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Z0-9]{8,64}", value):
        raise APIError(0, "INVALID_PROVIDER_ID")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self):
        if settings.ROLE not in {"worker", "hooks", "owner"} or not settings.PAYPAL_ENABLED:
            raise PermissionError("PayPal credentials are restricted to enabled trusted processes")
        if not settings.PAYPAL_CLIENT_ID or not settings.PAYPAL_CLIENT_SECRET:
            raise APIError(0, "MISSING_CREDENTIALS")
        self.client_id = settings.PAYPAL_CLIENT_ID
        self.secret = settings.PAYPAL_CLIENT_SECRET
        self.token = ""
        self.token_expires = 0
        self.lock = threading.Lock()
        # No redirects (including 307/308) and no environment-selected API destination.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def _send(self, method, path, body, headers):
        request = urllib.request.Request(API_ORIGIN + path, body, headers, method=method)
        try:
            with self.opener.open(request, timeout=8) as response:
                if response.status not in {200, 201}:
                    raise APIError(response.status, "UNEXPECTED_STATUS")
                raw = response.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            # Do not include remote descriptions, request payloads, or credentials in exceptions/logs.
            code = "HTTP_ERROR"
            try:
                data = json.loads(exc.read(8192))
                details = data.get("details", [])
                candidate = details[0].get("issue", "HTTP_ERROR") if details else data.get("name", "HTTP_ERROR")
                if isinstance(candidate, str):
                    code = candidate
            except (ValueError, TypeError, AttributeError, IndexError):
                pass
            raise APIError(exc.code, code) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise APIError() from None
        if len(raw) > MAX_RESPONSE:
            raise APIError(0, "RESPONSE_TOO_LARGE")
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, UnicodeError):
            raise APIError(0, "INVALID_RESPONSE") from None

    def access_token(self, refresh=False):
        with self.lock:
            if not refresh and self.token and time.monotonic() < self.token_expires:
                return self.token
            basic = base64.b64encode(f"{self.client_id}:{self.secret}".encode()).decode()
            value = self._send("POST", "/v1/oauth2/token", b"grant_type=client_credentials", {
                "Authorization": "Basic " + basic, "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json",
            })
            token, expires = value.get("access_token"), value.get("expires_in")
            if not isinstance(token, str) or not token or len(token) > 16384 or type(expires) is not int or expires < 1:
                raise APIError(0, "INVALID_TOKEN_RESPONSE")
            self.token, self.token_expires = token, time.monotonic() + max(0, expires - 30)
            return token

    def request(self, method, path, payload=None, request_id=None, raw=None):
        body = raw if raw is not None else (json.dumps(payload, separators=(",", ":"), allow_nan=False).encode() if payload is not None else None)
        for attempt in range(2):
            headers = {"Authorization": "Bearer " + self.access_token(refresh=bool(attempt)),
                       "Content-Type": "application/json", "Accept": "application/json", "Prefer": "return=representation"}
            if request_id is not None:
                headers["PayPal-Request-Id"] = str(request_id)
            try:
                return self._send(method, path, body, headers)
            except APIError as exc:
                if exc.status != 401 or attempt:
                    raise

    def create(self, payload, request_id):
        return self.request("POST", "/v2/checkout/orders", payload, request_id)

    def order(self, provider_id):
        return self.request("GET", "/v2/checkout/orders/" + identifier(provider_id))

    def capture(self, provider_id, request_id):
        return self.request("POST", "/v2/checkout/orders/" + identifier(provider_id) + "/capture", {}, request_id)

    def receipt(self, capture_id):
        return self.request("GET", "/v2/payments/captures/" + identifier(capture_id))

    def verify(self, raw_body, headers):
        if not settings.PAYPAL_WEBHOOK_ID:
            raise APIError(0, "MISSING_WEBHOOK_ID")
        data = {"auth_algo": headers["PAYPAL-AUTH-ALGO"], "cert_url": headers["PAYPAL-CERT-URL"],
                "transmission_id": headers["PAYPAL-TRANSMISSION-ID"], "transmission_sig": headers["PAYPAL-TRANSMISSION-SIG"],
                "transmission_time": headers["PAYPAL-TRANSMISSION-TIME"], "webhook_id": settings.PAYPAL_WEBHOOK_ID}
        # Preserve the exact event bytes: PayPal signature verification depends on their formatting.
        raw = json.dumps(data, separators=(",", ":")).encode()[:-1] + b',"webhook_event":' + raw_body + b"}"
        return self.request("POST", "/v1/notifications/verify-webhook-signature", raw=raw).get("verification_status") == "SUCCESS"


_client = None
_identity = None
_client_lock = threading.Lock()


def client():
    global _client, _identity
    if settings.ROLE not in {"worker", "hooks", "owner"} or not settings.PAYPAL_ENABLED:
        raise PermissionError("PayPal API access requires an enabled trusted process")
    identity = hashlib.sha256((settings.PAYPAL_CLIENT_ID + "\0" + settings.PAYPAL_CLIENT_SECRET).encode()).digest()
    with _client_lock:
        if _client is None or identity != _identity:
            _client, _identity = Client(), identity
        return _client
