import uuid

from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.views import LoginView
from django.db import IntegrityError, transaction
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .middleware import allow_request, throttled
from .models import Account, CheckoutRequest, Entitlement, Order, Plan, SandboxPaymentRequest
from .payments import PaymentError, receive


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
    })


@require_POST
@login_required
def checkout(request):
    if not allow_request(request, "checkout", 20):
        return throttled()
    plan = get_object_or_404(Plan, pk=request.POST.get("plan"), active=True)
    try:
        nonce = uuid.UUID(request.POST.get("nonce", ""))
    except (ValueError, TypeError, AttributeError):
        return HttpResponse("无效的购买请求，请刷新页面。", status=400)
    try:
        with transaction.atomic():
            intent = CheckoutRequest.objects.create(id=nonce, account=request.user, plan=plan)
    except IntegrityError:
        intent = get_object_or_404(CheckoutRequest, pk=nonce, account=request.user, plan=plan)
    return redirect("order", order_id=intent.pk)


@login_required
def order(request, order_id):
    intent = get_object_or_404(CheckoutRequest.objects.select_related("plan"), pk=order_id, account=request.user)
    value = Order.objects.filter(pk=intent.pk, account=request.user).first()
    return render(request, "commerce/order.html", {"intent": intent, "order": value, "payment_requested": value and SandboxPaymentRequest.objects.filter(order=value).exists()})


@require_POST
@login_required
def sandbox_pay(request, order_id):
    if not allow_request(request, "sandbox-pay", 30):
        return throttled()
    value = get_object_or_404(Order, pk=order_id, account=request.user)
    if value.state != Order.State.WAITING or value.reservation_expires <= timezone.now():
        return HttpResponse("当前订单不能付款。", status=409)
    channel = request.POST.get("channel", "")
    if channel not in {"card", "paypal", "wechat", "alipay"}:
        return HttpResponse("请选择沙箱支付方式。", status=400)
    SandboxPaymentRequest.objects.get_or_create(order=value, defaults={"channel": channel})
    return redirect("order", order_id=value.pk)


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
