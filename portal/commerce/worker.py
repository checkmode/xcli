import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from . import bridge, payments
from .models import Account, CheckoutRequest, Entitlement, Order, ProvisionJob, RateBucket, SandboxCharge, SandboxPaymentRequest


def require_worker():
    if settings.ROLE not in {"worker", "owner"}:
        raise PermissionError("Worker role required")


def from_epoch(value):
    return datetime.fromtimestamp(value, dt_timezone.utc)


def prepare(request_id):
    require_worker()
    with transaction.atomic():
        intent = CheckoutRequest.objects.select_related("plan").get(pk=request_id)
        Account.objects.select_for_update().get(pk=intent.account_id)
        if Order.objects.filter(pk=request_id).exists():
            return
        values = dict(request=intent, account_id=intent.account_id, amount_minor=intent.plan.amount_minor,
                      currency=intent.plan.currency, term_seconds=intent.plan.term_seconds)
        if not intent.plan.active or Order.objects.filter(account_id=intent.account_id, state__in=[Order.State.WAITING, Order.State.PAID, Order.State.REVIEW]).exists():
            Order.objects.create(**values, state=Order.State.REJECTED, message="请先完成或等待当前订单结束。")
            return
        try:
            reservation = bridge.call({"action": "reserve", "operation_id": bridge.operation_id("reserve", intent.pk), "account_id": intent.account_id.hex})
        except bridge.BridgeError as exc:
            if exc.status not in {404, 409}:
                raise
            Order.objects.create(**values, state=Order.State.REJECTED, message="当前没有可用名额，或账户需要管理员核对。")
            return
        if reservation["expires"] <= time.time():
            Order.objects.create(**values, state=Order.State.EXPIRED, message="购买意向已过期，请重新创建。")
            return
        Order.objects.create(**values, reservation_id=reservation["reservation_id"], reservation_expires=from_epoch(reservation["expires"]))


def simulate_charge(order_id):
    require_worker()
    with transaction.atomic():
        order = Order.objects.select_for_update().get(pk=order_id)
        if SandboxCharge.objects.filter(order=order).exists():
            return
        if order.state != Order.State.WAITING or order.reservation_expires <= timezone.now():
            return
        SandboxCharge.objects.create(order=order, merchant=settings.SANDBOX_MERCHANT, amount_minor=order.amount_minor,
                                     currency=order.currency, paid_at=timezone.now())


def deliver_charge(order_id, deliver=None):
    require_worker()
    charge = SandboxCharge.objects.get(order_id=order_id)
    body = json.dumps(payments.event_payload(charge), sort_keys=True, separators=(",", ":")).encode()
    stamp = str(int(time.time()))
    digest = payments.signature(body, stamp)
    if deliver is not None:
        deliver(body, stamp, digest)
    else:
        url = urllib.parse.urlsplit(settings.SANDBOX_HOOK_URL)
        if url.scheme != "http" or url.hostname != "127.0.0.1" or url.path != "/webhooks/sandbox/" or url.username or url.query or url.fragment:
            raise ValueError("Sandbox callbacks must use the local loopback hook listener")
        request = urllib.request.Request(settings.SANDBOX_HOOK_URL, body, {
            "Content-Type": "application/json", "X-Sandbox-Timestamp": stamp, "X-Sandbox-Signature": digest,
        }, method="POST")
        # No redirects or proxy environment: the simulator has only one local destination.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=5) as response:
            if response.status != 200:
                raise OSError("Sandbox callback was not accepted")
    SandboxCharge.objects.filter(pk=order_id).update(delivered=True)


def provision(order_id, after_grant=None):
    require_worker()
    # Account lock serializes payment and renewal; the operation ID covers a lost RPC reply or DB rollback.
    with transaction.atomic():
        account_id = Order.objects.values_list("account_id", flat=True).get(pk=order_id)
        Account.objects.select_for_update().get(pk=account_id)
        job = ProvisionJob.objects.select_for_update().get(pk=order_id)
        if job.done or job.available_at > timezone.now():
            return
        job.attempts += 1
        try:
            try:
                result = bridge.call(job.payload)
            except bridge.BridgeError as exc:
                if exc.status != 409 or str(exc) != "Reservation expired or does not belong to this account":
                    raise
                # A confirmed rejection made no grant. Acquire capacity again before retrying.
                reservation = bridge.call({"action": "reserve", "operation_id": bridge.operation_id("recover", job.operation_id, job.attempts), "account_id": account_id.hex})
                job.payload = {**job.payload, "reservation_id": reservation["reservation_id"]}
                # Persist the new exact request before any grant. A crash must not change its hash.
                job.save(update_fields=["payload", "attempts"])
                job.available_at = timezone.now() + timedelta(seconds=1)
                job.save(update_fields=["available_at"])
                return
            if after_grant:
                after_grant()  # Fault injection in tests: process loss after gateway commit.
            status = bridge.call({"action": "status", "operation_id": bridge.operation_id("status", order_id), "account_id": account_id.hex})
        except (bridge.BridgeError, OSError, ValueError) as exc:
            job.last_error = f"{type(exc).__name__}:{getattr(exc, 'status', 'unavailable')}"
            job.available_at = timezone.now() + timedelta(seconds=min(300, 2 ** min(job.attempts, 8)))
            job.save(update_fields=["payload", "attempts", "last_error", "available_at"])
            if isinstance(exc, bridge.BridgeError) and exc.status in {404, 409, 422}:
                Order.objects.filter(pk=order_id).update(state=Order.State.REVIEW, message="付款记录已保留，账户状态需要人工核对。")
            return
        entitlement, _ = Entitlement.objects.get_or_create(account_id=account_id)
        if entitlement.version > result["version"]:
            raise RuntimeError("Entitlement version would move backwards")
        entitlement.version = result["version"]
        entitlement.expires = from_epoch(result["expires"])
        entitlement.subscription_url = result["links"]["subscription"]
        entitlement.applied = status["applied"]
        entitlement.save()
        order = Order.objects.get(pk=order_id)
        if status["applied"]:
            order.state, order.message = Order.State.ACTIVE, "权限已同步到测试节点。"
        elif status["offline"]:
            order.state, order.message = Order.State.READY, "沙箱权限已创建；此环境未连接真实代理节点。"
        else:
            order.state, order.message = Order.State.PAID, "权限已保存，等待测试节点同步。"
        order.save(update_fields=["state", "message", "updated_at"])
        job.done = bool(status["applied"] or status["offline"])
        job.last_error = ""
        job.available_at = timezone.now() + timedelta(seconds=3)
        job.save(update_fields=["done", "attempts", "last_error", "available_at"])


def tick(deliver=None):
    require_worker()
    work = 0
    Order.objects.filter(state=Order.State.WAITING, reservation_expires__lte=timezone.now()).update(state=Order.State.EXPIRED, message="订单支付窗口已结束；已提交的模拟付款会继续核对。")
    stages = [
        (lambda: CheckoutRequest.objects.filter(order__isnull=True).order_by("created_at"), prepare),
        (lambda: SandboxPaymentRequest.objects.filter(order__sandboxcharge__isnull=True, order__state=Order.State.WAITING), simulate_charge),
        (lambda: SandboxCharge.objects.filter(delivered=False), lambda pk: deliver_charge(pk, deliver)),
        (lambda: ProvisionJob.objects.filter(done=False, available_at__lte=timezone.now()), provision),
    ]
    for query, process in stages:
        for key in list(query().values_list("pk", flat=True)[:20]):
            process(key)
            work += 1
    RateBucket.objects.filter(expires__lt=timezone.now()).delete()
    return work
