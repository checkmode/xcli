import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models import Q
from django.utils import timezone


class PaymentProvider(models.TextChoices):
    SIMULATOR = "simulator", "本地模拟收银台"
    PAYPAL = "paypal_sandbox", "PayPal 官方 Sandbox"


class Account(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)


class Plan(models.Model):
    code = models.SlugField(primary_key=True)
    name = models.CharField(max_length=100)
    amount_minor = models.PositiveIntegerField()
    currency = models.CharField(max_length=3, default="USD")
    term_seconds = models.PositiveIntegerField()
    active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.CheckConstraint(condition=Q(amount_minor__gt=0, term_seconds__gte=1, term_seconds__lte=366 * 86400), name="plan_positive_price_bounded_term")]


class CheckoutRequest(models.Model):
    """Untrusted web intent. Only the worker can create an actual priced order."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, on_delete=models.PROTECT)
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT)
    payment_provider = models.CharField(max_length=24, choices=PaymentProvider.choices, default=PaymentProvider.SIMULATOR)
    created_at = models.DateTimeField(auto_now_add=True)


class Order(models.Model):
    class State(models.TextChoices):
        WAITING = "waiting", "等待沙箱付款"
        PAID = "paid", "付款已校验，等待开通"
        READY = "ready", "沙箱权限已创建"
        ACTIVE = "active", "节点权限已生效"
        EXPIRED = "expired", "订单已过期"
        REJECTED = "rejected", "暂时无法购买"
        REVIEW = "review", "需要核对"

    request = models.OneToOneField(CheckoutRequest, primary_key=True, on_delete=models.PROTECT, related_name="order")
    account = models.ForeignKey(Account, on_delete=models.PROTECT)
    state = models.CharField(max_length=16, choices=State.choices, default=State.WAITING)
    payment_provider = models.CharField(max_length=24, choices=PaymentProvider.choices, default=PaymentProvider.SIMULATOR)
    amount_minor = models.PositiveIntegerField()
    currency = models.CharField(max_length=3)
    term_seconds = models.PositiveIntegerField()
    reservation_id = models.CharField(max_length=32, blank=True)
    reservation_expires = models.DateTimeField(null=True)
    message = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def display_amount(self):
        return f"{self.amount_minor / 100:.2f} {self.currency}"


class SandboxPaymentRequest(models.Model):
    order = models.OneToOneField(Order, primary_key=True, on_delete=models.PROTECT)
    channel = models.CharField(max_length=12, choices=[(c, c) for c in ("card", "paypal", "wechat", "alipay")])
    created_at = models.DateTimeField(auto_now_add=True)


class SandboxCharge(models.Model):
    """Sandbox provider's authoritative charge; never writable by the web role."""
    order = models.OneToOneField(Order, primary_key=True, on_delete=models.PROTECT)
    transaction_id = models.UUIDField(default=uuid.uuid4, unique=True)
    event_id = models.UUIDField(default=uuid.uuid4, unique=True)
    merchant = models.CharField(max_length=100)
    amount_minor = models.PositiveIntegerField()
    currency = models.CharField(max_length=3)
    paid_at = models.DateTimeField()
    delivered = models.BooleanField(default=False)


class PaymentEvent(models.Model):
    event_id = models.UUIDField(primary_key=True)
    body_hash = models.CharField(max_length=64)
    provider = models.CharField(max_length=24, default=PaymentProvider.SIMULATOR)
    provider_reference = models.CharField(max_length=128, blank=True)
    received_at = models.DateTimeField(auto_now_add=True)


class Payment(models.Model):
    order = models.OneToOneField(Order, primary_key=True, on_delete=models.PROTECT)
    transaction_id = models.UUIDField(unique=True)
    event = models.ForeignKey(PaymentEvent, on_delete=models.PROTECT)
    amount_minor = models.PositiveIntegerField()
    currency = models.CharField(max_length=3)
    paid_at = models.DateTimeField()
    provider = models.CharField(max_length=24, default=PaymentProvider.SIMULATOR)
    provider_reference = models.CharField(max_length=128, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["provider", "provider_reference"], condition=~Q(provider_reference=""), name="payment_provider_reference_unique")]


class PayPalOrder(models.Model):
    """Durable API request and provider mapping. Only the trusted worker can write it."""
    order = models.OneToOneField(Order, primary_key=True, on_delete=models.PROTECT)
    create_request_id = models.UUIDField(default=uuid.uuid4, unique=True)
    capture_request_id = models.UUIDField(default=uuid.uuid4, unique=True)
    request_payload = models.JSONField()
    provider_id = models.CharField(max_length=64, unique=True, null=True, blank=True)
    approval_url = models.URLField(max_length=1024, blank=True)
    status = models.CharField(max_length=24, default="creating")
    capture_started_at = models.DateTimeField(null=True)
    attempts = models.PositiveIntegerField(default=0)
    next_attempt = models.DateTimeField(default=timezone.now)
    done = models.BooleanField(default=False)
    last_error = models.CharField(max_length=80, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class Entitlement(models.Model):
    account = models.OneToOneField(Account, primary_key=True, on_delete=models.PROTECT)
    version = models.PositiveIntegerField(default=0)
    issued_version = models.PositiveIntegerField(default=0)
    expires = models.DateTimeField(null=True)
    subscription_url = models.TextField(blank=True)
    applied = models.BooleanField(default=False)

    class Meta:
        constraints = [models.CheckConstraint(condition=Q(issued_version__gte=models.F("version")), name="issued_entitlement_not_behind_applied")]


class ProvisionJob(models.Model):
    order = models.OneToOneField(Order, primary_key=True, on_delete=models.PROTECT)
    operation_id = models.UUIDField(default=uuid.uuid4, unique=True)
    payload = models.JSONField()
    done = models.BooleanField(default=False)
    attempts = models.PositiveIntegerField(default=0)
    available_at = models.DateTimeField()
    last_error = models.CharField(max_length=120, blank=True)


class RateBucket(models.Model):
    key = models.CharField(max_length=64, primary_key=True)
    count = models.PositiveIntegerField(default=0)
    expires = models.DateTimeField()
