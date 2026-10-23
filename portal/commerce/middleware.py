import hashlib
from datetime import timedelta

from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone

from .models import RateBucket


def allow_request(request, scope, maximum):
    # Do not trust X-Forwarded-For on this listener. Edge integration is a later step.
    now = timezone.now()
    identity = request.META.get("REMOTE_ADDR", "unknown")
    bucket = hashlib.sha256(f"{scope}:{identity}:{int(now.timestamp()) // 900}".encode()).hexdigest()
    with transaction.atomic():
        RateBucket.objects.get_or_create(key=bucket, defaults={"expires": now + timedelta(minutes=16)})
        row = RateBucket.objects.select_for_update().get(pk=bucket)
        if row.count >= maximum:
            return False
        row.count += 1
        row.save(update_fields=["count"])
    return True


class SandboxHeaders:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Cache-Control"] = "no-store"
        response["X-Frame-Options"] = "DENY"
        response["Content-Security-Policy"] = "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response


def throttled():
    response = HttpResponse("请求过于频繁，请 15 分钟后重试。", status=429)
    response["Retry-After"] = "900"
    return response
