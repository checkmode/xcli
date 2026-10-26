import uuid

from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.views import LoginView
from django.conf import settings
from django.db import IntegrityError, transaction
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .middleware import allow_request, throttled
from .models import Account, CheckoutRequest, Entitlement, Order, PaymentProvider, PayPalOrder, Plan, SandboxPaymentRequest
from .payments import PaymentError, receive
from . import paypal, paypal_api


class SignupForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = Account
        fields = ("username",)


class LimitedLoginView(LoginView):
    def post(self, request, *args, **kwargs):
        if not allow_request(request, "login", 12):
            return throttled()
        return super().post(request, *args, **kwargs)


def home(request):
    return render(request, "commerce/home.html", {"plans": Plan.objects.filter(active=True)})


def signup(request):
    if request.method == "POST" and not allow_request(request, "signup", 5):
        return throttled()
    form = SignupForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        login(request, user)
        return redirect("account")
    return render(request, "registration/signup.html", {"form": form})


@login_required
def account(request):
    return render(request, "commerce/account.html", {
        "requests": CheckoutRequest.objects.filter(account=request.user).select_related("order", "plan").order_by("-created_at")[:30],
        "entitlement": Entitlement.objects.filter(account=request.user).first(),
        "plans": Plan.objects.filter(active=True), "nonce": uuid.uuid4(),
        "paypal_enabled": settings.PAYPAL_ENABLED,
    })


@require_POST
@login_required
def checkout(request):
    if not allow_request(request, "checkout", 20):
        return throttled()
    plan = get_object_or_404(Plan, pk=request.POST.get("plan"), active=True)
    provider = request.POST.get("payment_provider", PaymentProvider.SIMULATOR)
    if provider not in PaymentProvider.values or (provider == PaymentProvider.PAYPAL and (not settings.PAYPAL_ENABLED or plan.currency != "USD")):
        return HttpResponse("所选支付方式暂不可用。", status=400)
    try:
        nonce = uuid.UUID(request.POST.get("nonce", ""))
    except (ValueError, TypeError, AttributeError):
        return HttpResponse("无效的购买请求，请刷新页面。", status=400)
    try:
        with transaction.atomic():
            intent = CheckoutRequest.objects.create(id=nonce, account=request.user, plan=plan, payment_provider=provider)
    except IntegrityError:
        intent = get_object_or_404(CheckoutRequest, pk=nonce, account=request.user, plan=plan, payment_provider=provider)
    return redirect("order", order_id=intent.pk)


@login_required
def order(request, order_id):
    intent = get_object_or_404(CheckoutRequest.objects.select_related("plan"), pk=order_id, account=request.user)
    value = Order.objects.filter(pk=intent.pk, account=request.user).first()
    # Column grants keep frozen merchant API requests out of the public DB role.
    provider = PayPalOrder.objects.filter(pk=order_id).values("approval_url", "status", "done").first() if value and value.payment_provider == PaymentProvider.PAYPAL else None
    waiting = not value or (provider and not provider["done"] and provider["status"] in {"creating", "approval", "pending"}) or (value and value.state == Order.State.PAID)
    return render(request, "commerce/order.html", {"intent": intent, "order": value, "paypal": provider,
        "paypal_enabled": settings.PAYPAL_ENABLED, "auto_refresh": waiting,
        "payment_requested": value and SandboxPaymentRequest.objects.filter(order=value).exists()})


@require_POST
@login_required
def sandbox_pay(request, order_id):
    if not allow_request(request, "sandbox-pay", 30):
        return throttled()
    value = get_object_or_404(Order, pk=order_id, account=request.user)
    if value.payment_provider != PaymentProvider.SIMULATOR:
        return HttpResponse("此订单须通过 PayPal Sandbox 付款。", status=409)
    if value.state != Order.State.WAITING or value.reservation_expires <= timezone.now():
        return HttpResponse("当前订单不能付款。", status=409)
    channel = request.POST.get("channel", "")
    if channel not in {"card", "paypal", "wechat", "alipay"}:
        return HttpResponse("请选择沙箱支付方式。", status=400)
    SandboxPaymentRequest.objects.get_or_create(order=value, defaults={"channel": channel})
    return redirect("order", order_id=value.pk)


@login_required
def paypal_return(request, order_id):
    value = get_object_or_404(Order, pk=order_id, account=request.user, payment_provider=PaymentProvider.PAYPAL)
    provider = get_object_or_404(PayPalOrder.objects.only("order_id", "provider_id"), pk=value.pk)
    if request.GET.get("token") != provider.provider_id:
        return HttpResponse("PayPal 返回的订单编号不匹配。", status=400)
    # A return token/PayerID is not evidence of payment. Only the worker/API receipt can fulfill.
    return redirect("order", order_id=value.pk)


@login_required
def paypal_cancel(request, order_id):
    value = get_object_or_404(Order, pk=order_id, account=request.user, payment_provider=PaymentProvider.PAYPAL)
    return render(request, "commerce/paypal_cancel.html", {"order": value})


@csrf_exempt  # Dedicated machine-only listener; HMAC and provider receipt replace browser CSRF.
@require_POST
def sandbox_webhook(request):
    try:
        if request.content_type != "application/json":
            raise PaymentError("Invalid content type")
        created = receive(request.body, request.headers.get("X-Sandbox-Timestamp", ""), request.headers.get("X-Sandbox-Signature", ""))
    except PaymentError:
        return JsonResponse({"ok": False}, status=400)
    return JsonResponse({"ok": True, "created": created})


@csrf_exempt  # Dedicated listener; verify the PayPal signature and query its receipt independently.
@require_POST
def paypal_webhook(request):
    if not settings.PAYPAL_ENABLED or not settings.PAYPAL_WEBHOOK_ID:
        return JsonResponse({"ok": False}, status=404)
    try:
        if request.content_type != "application/json":
            raise PaymentError("Invalid content type")
        if not allow_request(request, "paypal-webhook", 300):
            return throttled()
        created = paypal.receive(request.body, request.headers)
    except PaymentError:
        return JsonResponse({"ok": False}, status=400)
    except paypal_api.APIError:
        return JsonResponse({"ok": False}, status=503)
    return JsonResponse({"ok": True, "created": created})
