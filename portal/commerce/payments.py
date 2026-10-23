"""A local payment simulator, not an integration with a real payment provider."""
import hashlib
import hmac
import json
import time
import uuid

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .bridge import operation_id
from .models import Account, Entitlement, Order, Payment, PaymentEvent, ProvisionJob, SandboxCharge


class PaymentError(ValueError):
    pass


def event_payload(charge):
    return {
        "event_id": charge.event_id.hex,
        "transaction_id": charge.transaction_id.hex,
        "order_id": charge.order_id.hex,
        "merchant": charge.merchant,
        "amount_minor": charge.amount_minor,
        "currency": charge.currency,
        "paid_at": int(charge.paid_at.timestamp()),
        "status": "paid",
        "mode": "sandbox",
    }


def signature(body, timestamp):
    if settings.ROLE not in {"worker", "hooks", "owner"} or len(settings.SANDBOX_SIGNING_KEY) < 32:
        raise PermissionError("Sandbox signing key is only available to trusted processes")
    return hmac.new(settings.SANDBOX_SIGNING_KEY.encode(), str(timestamp).encode() + b"." + body, hashlib.sha256).hexdigest()


def receive(body, timestamp, digest):
    if settings.ROLE not in {"hooks", "owner"}:
        raise PermissionError("Payment verification is not part of the web process")
    if len(body) > 8192 or not timestamp.isdecimal() or len(timestamp) > 12:
        raise PaymentError("Invalid callback")
    if abs(int(time.time()) - int(timestamp)) > 300 or not hmac.compare_digest(signature(body, timestamp), digest):
        raise PaymentError("Invalid callback signature or timestamp")
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict) or type(payload.get("amount_minor")) is not int or type(payload.get("paid_at")) is not int:
            raise ValueError()
        tx_id = uuid.UUID(payload["transaction_id"])
        charge = SandboxCharge.objects.select_related("order").get(transaction_id=tx_id)
    except (ValueError, KeyError, TypeError, SandboxCharge.DoesNotExist) as exc:
        raise PaymentError("Unknown sandbox transaction") from exc
    # Independent provider lookup: a signed event alone is not a payment receipt.
    if payload != event_payload(charge) or charge.merchant != settings.SANDBOX_MERCHANT:
        raise PaymentError("Provider receipt does not match callback")
    with transaction.atomic():
        Account.objects.select_for_update().get(pk=charge.order.account_id)
        order = Order.objects.select_for_update().get(pk=charge.order_id)
        if (charge.amount_minor, charge.currency) != (order.amount_minor, order.currency):
            raise PaymentError("Order amount or currency mismatch")
        if order.state == Order.State.REJECTED or not order.reservation_expires or charge.paid_at > order.reservation_expires:
            raise PaymentError("Payment is outside the order validity window")
        body_hash = hashlib.sha256(body).hexdigest()
        event, created = PaymentEvent.objects.get_or_create(event_id=charge.event_id, defaults={"body_hash": body_hash})
        if not created and event.body_hash != body_hash:
            raise PaymentError("Event identifier collision")
        payment = Payment.objects.filter(transaction_id=charge.transaction_id).first()
        if payment:
            if payment.order_id != order.pk:
                raise PaymentError("Transaction was already assigned to another order")
            return False
        if Payment.objects.filter(order=order).exists():
            raise PaymentError("Order is already paid by another transaction")
        entitlement, _ = Entitlement.objects.get_or_create(account_id=order.account_id)
        entitlement.issued_version += 1
        entitlement.save(update_fields=["issued_version"])
        Payment.objects.create(order=order, transaction_id=charge.transaction_id, event=event,
                               amount_minor=charge.amount_minor, currency=charge.currency, paid_at=charge.paid_at)
        operation = operation_id("grant", order.pk)
        ProvisionJob.objects.create(order=order, operation_id=uuid.UUID(operation), available_at=timezone.now(), payload={
            "action": "grant", "operation_id": operation, "account_id": order.account_id.hex,
            "reservation_id": order.reservation_id, "version": entitlement.issued_version, "term_seconds": order.term_seconds,
        })
        order.state = Order.State.PAID
        order.message = "沙箱收款已核对，正在创建权限。"
        order.save(update_fields=["state", "message", "updated_at"])
    return True
