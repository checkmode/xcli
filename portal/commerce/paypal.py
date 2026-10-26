"""Official PayPal Sandbox checkout, reconciliation, and authenticated notifications."""
import hashlib
import json
import re
import uuid
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from . import paypal_api
from .models import Account, Order, PaymentProvider, PayPalOrder
from .payments import PaymentError, record_verified_payment

PROVIDER = PaymentProvider.PAYPAL
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "xcli:paypal-sandbox")


def money(value):
    # The initial catalog supports USD only. Never round floating point input.
    if not isinstance(value, dict) or value.get("currency_code") != "USD" or not isinstance(value.get("value"), str):
        raise PaymentError("Unsupported PayPal amount")
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,2})?", value["value"]):
        raise PaymentError("Invalid PayPal amount")
    whole, _, fraction = value["value"].partition(".")
    return int(whole) * 100 + int(fraction.ljust(2, "0"))


def order_payload(order):
    reference = order.pk.hex
    return {"intent": "CAPTURE", "purchase_units": [{"reference_id": reference, "custom_id": reference,
        "invoice_id": "xcli-sandbox-" + reference, "description": "Xdistribute Sandbox access",
        "payee": {"merchant_id": settings.PAYPAL_MERCHANT_ID},
        "amount": {"currency_code": order.currency, "value": f"{order.amount_minor // 100}.{order.amount_minor % 100:02d}"}}],
        "payment_source": {"paypal": {"experience_context": {"brand_name": "Xdistribute Sandbox",
            "shipping_preference": "NO_SHIPPING", "user_action": "PAY_NOW",
            "return_url": settings.PUBLIC_ORIGIN + f"/orders/{order.pk}/paypal/return/",
            "cancel_url": settings.PUBLIC_ORIGIN + f"/orders/{order.pk}/paypal/cancel/"}}}}


def approval_link(data, provider_id):
    links = data.get("links", [])
    if not isinstance(links, list):
        raise PaymentError("Invalid PayPal approval links")
    for link in links:
        if not isinstance(link, dict):
            raise PaymentError("Invalid PayPal approval link")
        if link.get("rel") not in {"approve", "payer-action"} or link.get("method", "GET") != "GET":
            continue
        value = link.get("href", "")
        try:
            url = urlsplit(value)
            if (url.scheme == "https" and url.netloc == "www.sandbox.paypal.com" and url.path == "/checkoutnow"
                    and not url.fragment and parse_qs(url.query).get("token") == [provider_id]):
                return value
        except ValueError:
            pass
    raise PaymentError("PayPal did not return a Sandbox approval URL")


def validate_order(row, data):
    try:
        expected = row.request_payload["purchase_units"][0]
        units = data["purchase_units"]
        if data["id"] != row.provider_id or data["intent"] != "CAPTURE" or not isinstance(units, list) or len(units) != 1:
            raise ValueError()
        unit = units[0]
        for key in ("reference_id", "custom_id", "invoice_id"):
            if unit.get(key) != expected[key]:
                raise ValueError()
        if (unit["payee"]["merchant_id"] != expected["payee"]["merchant_id"]
                or money(unit["amount"]) != row.order.amount_minor or row.order.currency != "USD"):
            raise ValueError()
        captures = unit.get("payments", {}).get("captures", [])
        if not isinstance(captures, list) or len(captures) > 1 or any(not isinstance(c, dict) for c in captures):
            raise ValueError()
        return captures
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
        raise PaymentError("PayPal order does not match the local order") from exc


def verified_capture(row, capture, api):
    capture_id = paypal_api.identifier(capture.get("id"))
    receipt = api.receipt(capture_id)
    try:
        expected = row.request_payload["purchase_units"][0]
        if (receipt["id"] != capture_id or receipt["status"] != "COMPLETED" or capture["status"] != "COMPLETED"
                or receipt.get("final_capture") is not True or money(receipt["amount"]) != row.order.amount_minor
                or money(capture["amount"]) != row.order.amount_minor):
            raise ValueError()
        # Some capture responses omit payee/related_ids; order details already bind both.
        if receipt.get("payee", {}).get("merchant_id", expected["payee"]["merchant_id"]) != expected["payee"]["merchant_id"]:
            raise ValueError()
        related = receipt.get("supplementary_data", {}).get("related_ids", {}).get("order_id", row.provider_id)
        if related != row.provider_id:
            raise ValueError()
        paid_at = parse_datetime(receipt["create_time"])
        if paid_at is None or timezone.is_naive(paid_at) or paid_at > timezone.now() + timedelta(minutes=5):
            raise ValueError()
        return {"id": capture_id, "amount_minor": money(receipt["amount"]), "currency": "USD", "paid_at": paid_at}
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise PaymentError("PayPal capture is not a matching completed receipt") from exc


def settle(row, receipt, event_id=None, body_hash=None):
    reference = event_id or "capture:" + receipt["id"]
    canonical = json.dumps({"order": row.provider_id, "capture": receipt["id"], "amount_minor": receipt["amount_minor"],
                            "currency": receipt["currency"]}, sort_keys=True).encode()
    created = record_verified_payment(order_id=row.pk,
        transaction_id=uuid.uuid5(NAMESPACE, "capture:" + receipt["id"]), event_id=uuid.uuid5(NAMESPACE, "event:" + reference),
        body_hash=body_hash or hashlib.sha256(canonical).hexdigest(), amount_minor=receipt["amount_minor"],
        currency=receipt["currency"], paid_at=receipt["paid_at"], provider=PROVIDER,
        transaction_reference=receipt["id"], event_reference=reference)
    row.status, row.done, row.approval_url, row.last_error = "completed", True, "", ""
    row.save(update_fields=["status", "done", "approval_url", "last_error"])
    return created


def review(row, reason):
    row.status, row.done, row.approval_url, row.last_error = "review", True, "", reason
    row.save(update_fields=["status", "done", "approval_url", "last_error"])
    Order.objects.filter(pk=row.pk).update(state=Order.State.REVIEW, message="PayPal 订单需要核对；请勿重复付款。")


def process(order_id):
    if settings.ROLE not in {"worker", "owner"} or not settings.PAYPAL_ENABLED:
        raise PermissionError("PayPal checkout requires the enabled worker")
    # Lock order is identical to receipt delivery: account, local order, provider row.
    with transaction.atomic():
        account_id = Order.objects.values_list("account_id", flat=True).get(pk=order_id)
        Account.objects.select_for_update().get(pk=account_id)
        order = Order.objects.select_for_update().get(pk=order_id)
        row = PayPalOrder.objects.select_for_update().get(pk=order_id)
        row.order = order
        if row.done or row.next_attempt > timezone.now():
            return
        row.attempts += 1
        row.next_attempt = timezone.now() + timedelta(seconds=15)
        row.last_error = ""
        try:
            api = paypal_api.client()
            if not row.provider_id:
                if order.reservation_expires <= timezone.now():
                    row.status, row.done = "expired", True
                else:
                    result = api.create(row.request_payload, row.create_request_id)
                    row.provider_id = paypal_api.identifier(result.get("id"))
                    row.approval_url = approval_link(result, row.provider_id)
                    row.status = "approval"
                    # A retry uses the frozen payload and same stored PayPal-Request-Id.
                    row.save(update_fields=["provider_id", "approval_url", "status"])
            if row.provider_id:
                data = api.order(row.provider_id)
                captures = validate_order(row, data)
                if not captures and data.get("status") == "APPROVED" and order.reservation_expires > timezone.now():
                    row.capture_started_at = row.capture_started_at or timezone.now()
                    row.save(update_fields=["capture_started_at"])
                    api.capture(row.provider_id, row.capture_request_id)
                    # Never fulfill from a browser return or an unverified POST response.
                    data = api.order(row.provider_id)
                    captures = validate_order(row, data)
                if captures:
                    status = captures[0].get("status")
                    if status == "COMPLETED":
                        settle(row, verified_capture(row, captures[0], api))
                    elif status == "PENDING":
                        row.status, row.approval_url = "pending", ""
                    else:
                        review(row, "CAPTURE_NOT_COMPLETED")
                elif data.get("status") in {"VOIDED", "COMPLETED"}:
                    review(row, "ORDER_WITHOUT_CAPTURE")
                elif order.reservation_expires <= timezone.now():
                    row.status, row.approval_url = "expired", ""
                if not row.done and row.created_at < timezone.now() - timedelta(days=3):
                    review(row, "RECONCILIATION_TIMEOUT")
        except paypal_api.APIError as exc:
            row.last_error = f"{exc.status}:{exc.code}"[:80]
            row.next_attempt = timezone.now() + timedelta(seconds=min(300, 2 ** min(row.attempts, 8)))
        except PaymentError:
            review(row, "RECEIPT_MISMATCH")
        row.save(update_fields=["attempts", "next_attempt", "status", "done", "approval_url", "last_error"])


def receive(body, headers):
    if settings.ROLE not in {"hooks", "owner"} or not settings.PAYPAL_ENABLED:
        raise PermissionError("PayPal notifications require the enabled hook process")
    if len(body) > 65536:
        raise PaymentError("PayPal notification is too large")
    required = ("PAYPAL-AUTH-ALGO", "PAYPAL-CERT-URL", "PAYPAL-TRANSMISSION-ID", "PAYPAL-TRANSMISSION-SIG", "PAYPAL-TRANSMISSION-TIME")
    if any(not isinstance(headers.get(k), str) or not 1 <= len(headers[k]) <= 4096 for k in required):
        raise PaymentError("Missing PayPal notification headers")
    # The certificate URL is sent only to PayPal's verification API, never fetched locally.
    try:
        cert = urlsplit(headers["PAYPAL-CERT-URL"])
        if (headers["PAYPAL-AUTH-ALGO"] != "SHA256withRSA" or cert.scheme != "https"
                or cert.netloc not in {"api.sandbox.paypal.com", "api-m.sandbox.paypal.com"}
                or not re.fullmatch(r"/v1/notifications/certs/[A-Za-z0-9-]+", cert.path) or cert.query or cert.fragment):
            raise ValueError()
        event = json.loads(body)
        event_id = event["id"]
        if not isinstance(event_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", event_id):
            raise ValueError()
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise PaymentError("Invalid PayPal notification") from exc
    api = paypal_api.client()
    if not api.verify(body, headers):
        raise PaymentError("PayPal signature verification failed")
    if event.get("event_type") not in {"PAYMENT.CAPTURE.COMPLETED", "PAYMENT.CAPTURE.PENDING", "PAYMENT.CAPTURE.DENIED"}:
        return False
    try:
        resource = event["resource"]
        capture_id = paypal_api.identifier(resource["id"])
        provider_id = paypal_api.identifier(resource["supplementary_data"]["related_ids"]["order_id"])
    except (KeyError, TypeError, paypal_api.APIError) as exc:
        raise PaymentError("Invalid PayPal capture notification") from exc
    found = PayPalOrder.objects.filter(provider_id=provider_id).first()
    if found is None:
        # Could precede a lost create response. The durable create request and polling recover it.
        return False
    with transaction.atomic():
        account_id = Order.objects.values_list("account_id", flat=True).get(pk=found.pk)
        Account.objects.select_for_update().get(pk=account_id)
        Order.objects.select_for_update().get(pk=found.pk)
        row = PayPalOrder.objects.select_for_update().select_related("order").get(pk=found.pk)
        captures = validate_order(row, api.order(provider_id))
        if len(captures) != 1 or captures[0].get("id") != capture_id:
            raise PaymentError("PayPal event does not belong to the stored order")
        if captures[0].get("status") != "COMPLETED":
            row.next_attempt = timezone.now()
            row.save(update_fields=["next_attempt"])
            return False
        receipt = verified_capture(row, captures[0], api)
        # Check notification fields as well as the independently queried provider receipt.
        if event["event_type"] == "PAYMENT.CAPTURE.COMPLETED" and (resource.get("status") != "COMPLETED" or money(resource.get("amount")) != row.order.amount_minor):
            raise PaymentError("PayPal notification amount or status mismatch")
        return settle(row, receipt, event_id, hashlib.sha256(body).hexdigest())
