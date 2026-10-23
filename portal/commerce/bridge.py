import json
import socket
import uuid

from django.conf import settings


class BridgeError(Exception):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def operation_id(namespace, *parts):
    return uuid.uuid5(uuid.NAMESPACE_URL, "xcli-portal:" + namespace + ":" + ":".join(map(str, parts))).hex


def call(payload):
    if settings.ROLE not in {"worker", "owner"}:
        raise PermissionError("Only the worker may request provisioning")
    request = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(request) > 8192:
        raise ValueError("Provision request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(settings.PROVISION_SOCKET)
        client.sendall(request)
        result = b""
        while not result.endswith(b"\n"):
            chunk = client.recv(4096)
            if not chunk:
                raise OSError("Incomplete provision response")
            result += chunk
            if len(result) > 65536:
                raise OSError("Provision response too large")
    value = json.loads(result)
    if not value.get("ok"):
        raise BridgeError(value.get("status", 503), value.get("error", "Provisioning failed"))
    return value["result"]
