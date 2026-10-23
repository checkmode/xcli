import concurrent.futures
import copy
import json
import re
import time
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.db import DatabaseError, close_old_connections, connection, transaction
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from . import bridge, payments, worker
from .db_roles import apply_roles
from .models import Account, CheckoutRequest, Entitlement, Order, Payment, PaymentEvent, Plan, ProvisionJob, SandboxCharge, SandboxPaymentRequest


class FakeBridge:
    """Model the durable external boundary; C++ and live tests exercise the real implementation."""
    def __init__(self):
        self.results = {}
        self.accounts = {}
        self.fail = False

    def __call__(self, payload):
        if self.fail:
            raise OSError("controller unavailable")
        account = payload["account_id"]
        if payload["action"] == "status":
            result = copy.deepcopy(self.accounts[account])
            return {**result, "applied": False, "offline": True}
        key = payload["operation_id"]
        digest = json.dumps(payload, sort_keys=True)
        if key in self.results:
            old, result = self.results[key]
            if old != digest:
                raise bridge.BridgeError(409, "Operation identifier was reused with different parameters")
            return copy.deepcopy(result)
        if payload["action"] == "reserve":
            result = {"reservation_id": key, "expires": int(time.time()) + 1800}
        else:
            previous = self.accounts.get(account, {"version": 0, "expires": 0})
            if payload["version"] != previous["version"] + 1:
                raise bridge.BridgeError(409, "Entitlement version is stale or out of order")
            result = {"version": payload["version"], "expires": max(int(time.time()), previous["expires"]) + payload["term_seconds"],
                      "links": {"subscription": f"https://sandbox.invalid/s/{account}"}}
            self.accounts[account] = result
        self.results[key] = (digest, copy.deepcopy(result))
        return result


@override_settings(ROLE="owner", SANDBOX_SIGNING_KEY="sandbox-test-key-" * 4, PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class CommerceTests(TestCase):
    def setUp(self):
        self.plan = Plan.objects.create(code="test-30d", name="Test", amount_minor=100, currency="USD", term_seconds=30 * 86400)
        self.account = Account.objects.create_user(username="alice", password="only-a-local-test-password")
        self.fake = FakeBridge()
        self.mock = patch("commerce.bridge.call", side_effect=self.fake)
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def order(self, account=None):
        intent = CheckoutRequest.objects.create(account=account or self.account, plan=self.plan)
        worker.prepare(intent.pk)
        return Order.objects.get(pk=intent.pk)

    def charge(self, order):
        worker.simulate_charge(order.pk)
        return SandboxCharge.objects.get(order=order)

    def event(self, charge, changes=None, timestamp=None):
        payload = payments.event_payload(charge)
        payload.update(changes or {})
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        stamp = str(timestamp or int(time.time()))
        return body, stamp, payments.signature(body, stamp)

    def test_each_sandbox_channel_completes_and_replay_does_not_extend(self):
        for channel in ("card", "paypal", "wechat", "alipay"):
            account = Account.objects.create_user(username=channel)
            order = self.order(account)
            SandboxPaymentRequest.objects.create(order=order, channel=channel)
            worker.tick(deliver=payments.receive)
            order.refresh_from_db()
            self.assertEqual(order.state, Order.State.READY)
            entitlement = Entitlement.objects.get(account=account)
            first_expiry = entitlement.expires
            charge = SandboxCharge.objects.get(order=order)
            self.assertFalse(payments.receive(*self.event(charge)))
            worker.tick(deliver=payments.receive)
            entitlement.refresh_from_db()
            self.assertEqual(entitlement.version, 1)
            self.assertEqual(entitlement.expires, first_expiry)
            self.assertEqual(Payment.objects.filter(order=order).count(), 1)

    def test_signed_callback_requires_matching_provider_and_order(self):
        order = self.order()
        charge = self.charge(order)
        for change in ({"amount_minor": 1}, {"currency": "CNY"}, {"merchant": "other"}, {"status": "pending"}, {"mode": "live"}, {"amount_minor": True}):
            with self.assertRaises(payments.PaymentError):
                payments.receive(*self.event(charge, change))
        # Even a perfectly signed provider receipt is rejected if the order differs.
        charge.amount_minor = 200
        charge.save()
        with self.assertRaises(payments.PaymentError):
            payments.receive(*self.event(charge))
        self.assertFalse(Payment.objects.exists())
        self.assertFalse(PaymentEvent.objects.exists())
        self.assertFalse(ProvisionJob.objects.exists())

    def test_forged_and_expired_signatures_never_create_payment(self):
        charge = self.charge(self.order())
        body, stamp, _ = self.event(charge)
        with self.assertRaises(payments.PaymentError):
            payments.receive(body, stamp, "0" * 64)
        with self.assertRaises(payments.PaymentError):
            payments.receive(*self.event(charge, timestamp=int(time.time()) - 600))
        self.assertFalse(Payment.objects.exists())

    def test_lost_worker_after_external_commit_replays_exact_operation(self):
        order = self.order()
        payments.receive(*self.event(self.charge(order)))

        class SimulatedProcessLoss(BaseException):
            pass

        def crash():
            raise SimulatedProcessLoss()

        with self.assertRaises(SimulatedProcessLoss):
            worker.provision(order.pk, after_grant=crash)
        external_expiry = self.fake.accounts[self.account.pk.hex]["expires"]
        self.assertEqual(Entitlement.objects.get(account=self.account).version, 0)
        self.assertFalse(ProvisionJob.objects.get(pk=order.pk).done)
        worker.provision(order.pk)
        entitlement = Entitlement.objects.get(account=self.account)
        self.assertEqual(int(entitlement.expires.timestamp()), external_expiry)
        self.assertEqual(entitlement.version, 1)

    def test_controller_outage_retains_paid_job_then_recovers(self):
        order = self.order()
        payments.receive(*self.event(self.charge(order)))
        self.fake.fail = True
        worker.provision(order.pk)
        job = ProvisionJob.objects.get(pk=order.pk)
        self.assertFalse(job.done)
        self.assertEqual(job.attempts, 1)
        self.assertTrue(Payment.objects.filter(order=order).exists())
        self.fake.fail = False
        ProvisionJob.objects.filter(pk=order.pk).update(available_at=timezone.now())
        worker.provision(order.pk)
        self.assertTrue(ProvisionJob.objects.get(pk=order.pk).done)

    def test_renewal_extends_once_and_keeps_subscription(self):
        order = self.order()
        payments.receive(*self.event(self.charge(order)))
        worker.provision(order.pk)
        original = Entitlement.objects.get(account=self.account)
        second = self.order()
        payments.receive(*self.event(self.charge(second)))
        worker.provision(second.pk)
        renewed = Entitlement.objects.get(account=self.account)
        self.assertEqual(renewed.version, 2)
        self.assertEqual(renewed.expires, original.expires + timedelta(days=30))
        self.assertEqual(renewed.subscription_url, original.subscription_url)

    def test_duplicate_open_order_is_rejected_without_second_reservation(self):
        first = self.order()
        second = self.order()
        self.assertEqual(first.state, Order.State.WAITING)
        self.assertEqual(second.state, Order.State.REJECTED)
        self.assertEqual(len(self.fake.results), 1)

    def test_late_paid_callback_and_new_order_get_distinct_entitlement_versions(self):
        first = self.order()
        old_charge = self.charge(first)
        Order.objects.filter(pk=first.pk).update(state=Order.State.EXPIRED)
        second = self.order()
        new_charge = self.charge(second)
        payments.receive(*self.event(old_charge))
        payments.receive(*self.event(new_charge))
        self.assertEqual(ProvisionJob.objects.get(pk=first.pk).payload["version"], 1)
        self.assertEqual(ProvisionJob.objects.get(pk=second.pk).payload["version"], 2)
        worker.provision(first.pk)
        worker.provision(second.pk)
        self.assertEqual(Entitlement.objects.get(account=self.account).version, 2)

    def test_expired_order_never_creates_sandbox_charge(self):
        order = self.order()
        Order.objects.filter(pk=order.pk).update(reservation_expires=timezone.now() - timedelta(seconds=1))
        SandboxPaymentRequest.objects.create(order=order, channel="card")
        worker.tick(deliver=payments.receive)
        self.assertFalse(SandboxCharge.objects.exists())
        order.refresh_from_db()
        self.assertEqual(order.state, Order.State.EXPIRED)

    def test_order_and_payment_routes_are_scoped_to_logged_in_account(self):
        order = self.order()
        other = Account.objects.create_user(username="bob")
        self.client.force_login(other)
        self.assertEqual(self.client.get(f"/orders/{order.pk}/").status_code, 404)
        self.assertEqual(self.client.post(f"/orders/{order.pk}/sandbox-pay/", {"channel": "card"}).status_code, 404)
        self.assertEqual(self.client.post("/checkout/", {"nonce": order.pk, "plan": self.plan.pk}).status_code, 404)
        self.assertFalse(SandboxPaymentRequest.objects.exists())

    def test_signup_csrf_login_and_nonce_idempotency(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post("/signup/", {"username": "new"}).status_code, 403)
        client.get("/signup/")
        csrf = client.cookies["xportal_csrf"].value
        result = client.post("/signup/", {"username": "new", "password1": "local-sandbox-long-password", "password2": "local-sandbox-long-password", "csrfmiddlewaretoken": csrf})
        self.assertEqual(result.status_code, 302)
        response = client.get("/account/")
        self.assertEqual(response["Referrer-Policy"], "same-origin")
        nonce = re.search(r'name="nonce" value="([^"]+)"', response.content.decode()).group(1)
        csrf = client.cookies["xportal_csrf"].value
        form = {"nonce": nonce, "plan": self.plan.pk, "amount_minor": 1, "csrfmiddlewaretoken": csrf}
        first, second = client.post("/checkout/", form), client.post("/checkout/", form)
        self.assertEqual(first.url, second.url)
        self.assertEqual(CheckoutRequest.objects.filter(account__username="new").count(), 1)
        self.assertEqual(client.get("/webhooks/sandbox/").status_code, 404)
        self.assertEqual(client.get("/api/provision").status_code, 404)
        self.assertEqual(client.post("/checkout/", form, HTTP_ORIGIN="null").status_code, 403)
        self.assertEqual(client.post("/checkout/", form, HTTP_ORIGIN="https://foreign.example").status_code, 403)

    def test_public_database_role_cannot_write_payment_or_provisioning_state(self):
        apply_roles()
        for sql in (
            "UPDATE commerce_plan SET amount_minor=1",
            "UPDATE commerce_order SET state='active'",
            "DELETE FROM commerce_paymentevent",
            "DELETE FROM commerce_payment",
            "DELETE FROM commerce_provisionjob",
            "UPDATE commerce_entitlement SET version=100",
            "SELECT * FROM commerce_sandboxcharge",
        ):
            with self.assertRaises(DatabaseError):
                with transaction.atomic(), connection.cursor() as cursor:
                    cursor.execute("SET LOCAL ROLE xportal_web")
                    cursor.execute(sql)

    @override_settings(ROLE="web")
    def test_public_process_cannot_verify_callbacks_or_run_worker(self):
        with self.assertRaises(PermissionError):
            worker.tick()
        with self.assertRaises(PermissionError):
            payments.receive(b"{}", "123", "")


@override_settings(ROLE="owner", SANDBOX_SIGNING_KEY="sandbox-concurrency-key-" * 4)
class ConcurrentCallbackTests(TransactionTestCase):
    def test_concurrent_verified_callbacks_create_one_payment_and_one_job(self):
        account = Account.objects.create_user(username="concurrent")
        plan = Plan.objects.create(code="test", name="Test", amount_minor=100, currency="USD", term_seconds=86400)
        intent = CheckoutRequest.objects.create(account=account, plan=plan)
        order = Order.objects.create(request=intent, account=account, amount_minor=100, currency="USD", term_seconds=86400,
                                     reservation_id=uuid.uuid4().hex, reservation_expires=timezone.now() + timedelta(minutes=30))
        worker.simulate_charge(order.pk)
        charge = SandboxCharge.objects.get(order=order)
        body = json.dumps(payments.event_payload(charge), sort_keys=True, separators=(",", ":")).encode()
        stamp = str(int(time.time()))
        digest = payments.signature(body, stamp)

        def receive():
            close_old_connections()
            try:
                return payments.receive(body, stamp, digest)
            finally:
                close_old_connections()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: receive(), range(8)))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(Payment.objects.count(), 1)
        self.assertEqual(PaymentEvent.objects.count(), 1)
        self.assertEqual(ProvisionJob.objects.count(), 1)
