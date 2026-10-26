import concurrent.futures
import copy
import io
import json
import os
import tempfile
import urllib.error
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command, CommandError
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import Client, SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from config.paypal import configuration
from . import paypal, paypal_api, worker
from .db_roles import apply_roles
from .models import Account, CheckoutRequest, Entitlement, Order, Payment, PaymentEvent, PaymentProvider, PayPalOrder, Plan, ProvisionJob, SandboxCharge
from .payments import PaymentError
from .tests import FakeBridge

CONFIG = dict(ROLE="owner", PAYPAL_ENABLED=True, PAYPAL_CLIENT_ID="sandbox-test-client",
              PAYPAL_CLIENT_SECRET="sandbox-test-secret", PAYPAL_MERCHANT_ID="TESTMERCHANT1",
              PAYPAL_WEBHOOK_ID="TESTWEBHOOK1", PUBLIC_ORIGIN="https://portal.example.test")
HEADERS = {"PAYPAL-AUTH-ALGO": "SHA256withRSA", "PAYPAL-CERT-URL": "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-test",
           "PAYPAL-TRANSMISSION-ID": "test-transmission", "PAYPAL-TRANSMISSION-SIG": "test-signature",
           "PAYPAL-TRANSMISSION-TIME": "2026-10-23T00:00:00Z"}


class FakePayPal:
    """Stateful provider boundary: remote success can outlive a lost HTTP response."""
    def __init__(self):
        self.order_id = "5O190127TN364715T"
        self.capture_id = "3Y662965014333303"
        self.creates, self.captures = [], []
        self.payload = None
        self.status = "PAYER_ACTION_REQUIRED"
        self.capture_status = None
        self.capture_time = None
        self.lose_create_reply = False
        self.lose_capture_reply = False
        self.valid_signature = True

    def create(self, payload, request_id):
        self.creates.append((str(request_id), copy.deepcopy(payload)))
        if self.payload is None:
            self.payload = copy.deepcopy(payload)
        if self.lose_create_reply:
            self.lose_create_reply = False
            raise paypal_api.APIError()
        return {"id": self.order_id, "status": self.status, "links": [{"rel": "payer-action", "method": "GET",
                "href": "https://www.sandbox.paypal.com/checkoutnow?token=" + self.order_id}]}

    def order(self, provider_id):
        assert provider_id == self.order_id
        result = {"id": self.order_id, "intent": "CAPTURE", "status": self.status,
                  "purchase_units": copy.deepcopy(self.payload["purchase_units"])}
        if self.capture_status:
            result["purchase_units"][0]["payments"] = {"captures": [self.receipt(self.capture_id)]}
        return result

    def capture(self, provider_id, request_id):
        assert provider_id == self.order_id
        self.captures.append(str(request_id))
        self.status, self.capture_status = "COMPLETED", "COMPLETED"
        self.capture_time = timezone.now().isoformat()
        if self.lose_capture_reply:
            self.lose_capture_reply = False
            raise paypal_api.APIError()
        return self.order(provider_id)

    def receipt(self, capture_id):
        assert capture_id == self.capture_id
        unit = self.payload["purchase_units"][0]
        return {"id": capture_id, "status": self.capture_status, "final_capture": True, "amount": copy.deepcopy(unit["amount"]),
                "payee": copy.deepcopy(unit["payee"]), "create_time": self.capture_time or timezone.now().isoformat(),
                "supplementary_data": {"related_ids": {"order_id": self.order_id}}}

    def verify(self, body, headers):
        return self.valid_signature

    def event(self):
        return json.dumps({"id": "WH-CAPTURE-TEST", "event_type": "PAYMENT.CAPTURE.COMPLETED",
                           "resource": self.receipt(self.capture_id)}, sort_keys=True).encode()


@override_settings(**CONFIG)
class PayPalCheckoutTests(TestCase):
    def setUp(self):
        self.account = Account.objects.create_user(username="paypal-buyer")
        self.plan = Plan.objects.create(code="paypal", name="Sandbox", amount_minor=100, currency="USD", term_seconds=86400)
        self.bridge = FakeBridge()
        self.api = FakePayPal()
        self.bridge_patch = patch("commerce.bridge.call", side_effect=self.bridge)
        self.api_patch = patch("commerce.paypal_api.client", return_value=self.api)
        self.bridge_patch.start(); self.api_patch.start()
        self.addCleanup(self.bridge_patch.stop); self.addCleanup(self.api_patch.stop)
        self.intent = CheckoutRequest.objects.create(account=self.account, plan=self.plan, payment_provider=PaymentProvider.PAYPAL)
        worker.prepare(self.intent.pk)
        self.order = Order.objects.get(pk=self.intent.pk)

    def due(self):
        PayPalOrder.objects.filter(pk=self.order.pk).update(next_attempt=timezone.now())

    def create(self):
        paypal.process(self.order.pk)
        return PayPalOrder.objects.get(pk=self.order.pk)

    def complete_remotely(self):
        row = self.create()
        self.api.capture(self.api.order_id, row.capture_request_id)
        return row

    def test_full_checkout_and_polling_provisions_without_browser_return(self):
        row = self.create()
        self.assertEqual(row.status, "approval")
        self.assertFalse(Payment.objects.exists())
        self.api.status = "APPROVED"
        self.due(); worker.tick()
        self.order.refresh_from_db()
        self.assertEqual(self.order.state, Order.State.READY)
        self.assertEqual(Payment.objects.get().provider_reference, self.api.capture_id)
        self.assertEqual(Entitlement.objects.get().version, 1)
        worker.tick()
        self.assertEqual(len(self.api.captures), 1)

    def test_create_timeout_reuses_frozen_request_and_id(self):
        original = PayPalOrder.objects.get(pk=self.order.pk).request_payload
        self.api.lose_create_reply = True
        paypal.process(self.order.pk)
        self.assertIsNone(PayPalOrder.objects.get(pk=self.order.pk).provider_id)
        self.due()
        with override_settings(PUBLIC_ORIGIN="https://changed.example.test", PAYPAL_MERCHANT_ID="CHANGEDMERCHANT"):
            paypal.process(self.order.pk)
        self.assertEqual(self.api.creates[0], self.api.creates[1])
        self.assertEqual(self.api.creates[1][1], original)

    def test_capture_timeout_reconciles_without_second_charge(self):
        self.create(); self.api.status = "APPROVED"; self.api.lose_capture_reply = True
        self.due(); paypal.process(self.order.pk)
        self.assertFalse(Payment.objects.exists())
        self.assertIsNotNone(PayPalOrder.objects.get(pk=self.order.pk).capture_started_at)
        self.due(); paypal.process(self.order.pk)
        self.assertEqual(Payment.objects.count(), 1)
        self.assertEqual(len(self.api.captures), 1)

    def test_pending_capture_does_not_grant_until_completed(self):
        self.complete_remotely(); self.api.capture_status = "PENDING"
        self.due(); paypal.process(self.order.pk)
        self.assertEqual(PayPalOrder.objects.get(pk=self.order.pk).status, "pending")
        self.assertFalse(Payment.objects.exists()); self.assertFalse(ProvisionJob.objects.exists())
        self.api.capture_status = "COMPLETED"
        self.due(); paypal.process(self.order.pk)
        self.assertEqual(Payment.objects.count(), 1)

    def test_denied_capture_never_grants(self):
        self.complete_remotely(); self.api.capture_status = "DECLINED"
        self.due(); paypal.process(self.order.pk)
        self.order.refresh_from_db()
        self.assertEqual(self.order.state, Order.State.REVIEW)
        self.assertFalse(Payment.objects.exists()); self.assertFalse(ProvisionJob.objects.exists())

    def test_expired_order_is_not_captured_but_existing_payment_is_reconciled(self):
        self.create(); self.api.status = "APPROVED"
        Order.objects.filter(pk=self.order.pk).update(reservation_expires=timezone.now() - timedelta(seconds=1))
        self.due(); paypal.process(self.order.pk)
        self.assertEqual(self.api.captures, [])
        self.assertFalse(Payment.objects.exists())
        self.api.capture(self.api.order_id, "external-completion")
        self.due(); paypal.process(self.order.pk)
        self.assertEqual(Payment.objects.count(), 1)
        self.assertEqual(ProvisionJob.objects.count(), 1)

    def test_browser_return_cancel_and_simulation_cannot_mark_paypal_paid(self):
        self.create()
        client = Client(); client.force_login(self.account)
        base = f"/orders/{self.order.pk}"
        self.assertEqual(client.get(base + "/paypal/return/?token=forged").status_code, 400)
        self.assertEqual(client.get(base + "/paypal/return/?token=" + self.api.order_id).status_code, 302)
        self.assertEqual(client.get(base + "/paypal/cancel/").status_code, 200)
        self.assertEqual(client.post(base + "/sandbox-pay/", {"channel": "paypal"}).status_code, 409)
        worker.simulate_charge(self.order.pk)
        self.assertFalse(SandboxCharge.objects.exists()); self.assertFalse(Payment.objects.exists())
        other = Account.objects.create_user(username="other")
        client.force_login(other)
        for suffix in ("/", "/paypal/return/?token=" + self.api.order_id, "/paypal/cancel/"):
            self.assertEqual(client.get(base + suffix).status_code, 404)

    def test_ui_distinguishes_official_paypal_and_hides_simulator_button(self):
        self.create()
        client = Client(); client.force_login(self.account)
        response = client.get(f"/orders/{self.order.pk}/")
        self.assertContains(response, "PayPal 官方 Sandbox")
        self.assertContains(response, "https://www.sandbox.paypal.com/checkoutnow?token=")
        self.assertNotContains(response, "模拟付款成功")
        self.assertContains(client.get("/account/"), 'value="paypal_sandbox"')

    def test_order_binding_amount_currency_merchant_and_custom_id_are_checked(self):
        row = self.create()
        for field, value in (("amount", {"currency_code": "USD", "value": "0.01"}),
                             ("amount", {"currency_code": "EUR", "value": "1.00"}),
                             ("payee", {"merchant_id": "OTHERSELLER"}), ("custom_id", uuid.uuid4().hex),
                             ("invoice_id", "other-invoice"), ("reference_id", "other-reference")):
            with self.subTest(field=field, value=value):
                data = self.api.order(row.provider_id); data["purchase_units"][0][field] = value
                with self.assertRaises(PaymentError):paypal.validate_order(row, data)
        self.assertFalse(Payment.objects.exists())

    def test_signature_and_independent_receipt_are_both_required(self):
        row = self.complete_remotely()
        self.api.valid_signature = False
        with self.assertRaises(PaymentError):paypal.receive(self.api.event(), HEADERS)
        self.api.valid_signature = True
        receipt = self.api.receipt(self.api.capture_id); receipt["amount"]["value"] = "0.01"
        with patch.object(self.api, "receipt", return_value=receipt), self.assertRaises(PaymentError):
            paypal.receive(self.api.event(), HEADERS)
        self.assertFalse(Payment.objects.exists()); self.assertFalse(ProvisionJob.objects.exists())

    def test_verified_webhook_with_wrong_body_amount_or_order_is_rejected(self):
        self.complete_remotely()
        event = json.loads(self.api.event())
        event["resource"]["amount"]["value"] = "0.01"
        with self.assertRaises(PaymentError):paypal.receive(json.dumps(event).encode(), HEADERS)
        event = json.loads(self.api.event()); event["resource"]["id"] = "OTHERCAPTURE12345"
        with self.assertRaises(PaymentError):paypal.receive(json.dumps(event).encode(), HEADERS)
        self.assertFalse(Payment.objects.exists())

    def test_completed_receipt_requires_full_capture_and_matching_payee(self):
        row = self.complete_remotely()
        capture = self.api.receipt(self.api.capture_id)
        for change in ({"final_capture": False}, {"payee": {"merchant_id": "OTHERSELLER"}},
                       {"status": "PENDING"}, {"supplementary_data": {"related_ids": {"order_id": "OTHERORDER12345"}}}):
            with self.subTest(change=change), patch.object(self.api, "receipt", return_value={**capture, **change}), self.assertRaises(PaymentError):
                paypal.verified_capture(row, capture, self.api)

    def test_webhook_duplicate_and_later_poll_do_not_extend_twice(self):
        self.complete_remotely(); body = self.api.event()
        self.assertTrue(paypal.receive(body, HEADERS))
        self.assertFalse(paypal.receive(body, HEADERS))
        self.due(); worker.tick()
        self.assertEqual(Payment.objects.count(), 1)
        self.assertEqual(ProvisionJob.objects.count(), 1)
        self.assertEqual(Entitlement.objects.get().version, 1)
        self.assertEqual(PaymentEvent.objects.get().provider_reference, "WH-CAPTURE-TEST")

    def test_poll_then_webhook_preserves_one_payment_and_both_event_references(self):
        self.complete_remotely(); self.due(); paypal.process(self.order.pk)
        self.assertFalse(paypal.receive(self.api.event(), HEADERS))
        self.assertEqual(Payment.objects.count(), 1)
        self.assertEqual(PaymentEvent.objects.count(), 2)
        self.assertEqual(Entitlement.objects.get().issued_version, 1)

    def test_webhook_route_is_separate_and_provider_outage_is_retryable(self):
        self.complete_remotely()
        headers = {"HTTP_" + k.replace("-", "_"): v for k, v in HEADERS.items()}
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post("/webhooks/paypal/", self.api.event(), content_type="application/json", **headers).status_code, 404)
        with override_settings(ROOT_URLCONF="config.hooks_urls", ROLE="hooks"):
            with patch.object(self.api, "verify", side_effect=paypal_api.APIError()):
                self.assertEqual(client.post("/webhooks/paypal/", self.api.event(), content_type="application/json", **headers).status_code, 503)
            self.api.valid_signature = False
            self.assertEqual(client.post("/webhooks/paypal/", self.api.event(), content_type="application/json", **headers).status_code, 400)
            self.api.valid_signature = True
            self.assertEqual(client.post("/webhooks/paypal/", self.api.event(), content_type="application/json", **headers).status_code, 200)

    def test_database_public_role_cannot_change_provider_state_or_read_request(self):
        self.create(); apply_roles()
        for sql in ("UPDATE commerce_paypalorder SET status='completed'", "SELECT request_payload FROM commerce_paypalorder",
                    "UPDATE commerce_payment SET provider_reference='FORGED'", "DELETE FROM commerce_paypalorder"):
            with self.subTest(sql=sql), self.assertRaises(DatabaseError):
                with transaction.atomic(), connection.cursor() as cursor:
                    cursor.execute("SET LOCAL ROLE xportal_web"); cursor.execute(sql)
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("SET LOCAL ROLE xportal_web")
            result = PayPalOrder.objects.values("approval_url", "status").get(pk=self.order.pk)
            self.assertEqual(result["status"], "approval")

    @override_settings(ROLE="web")
    def test_web_process_cannot_call_provider_or_accept_receipts(self):
        with self.assertRaises(PermissionError):paypal_api.Client()
        with self.assertRaises(PermissionError):paypal.process(self.order.pk)
        with self.assertRaises(PermissionError):paypal.receive(b"{}", {})

    def test_disabled_paypal_and_client_supplied_provider_are_rejected(self):
        client = Client(); client.force_login(self.account)
        for provider in ("paypal_live", "unknown"):
            self.assertEqual(client.post("/checkout/", {"plan": self.plan.pk, "nonce": uuid.uuid4(), "payment_provider": provider}).status_code, 400)
        with override_settings(PAYPAL_ENABLED=False):
            self.assertEqual(client.post("/checkout/", {"plan": self.plan.pk, "nonce": uuid.uuid4(), "payment_provider": "paypal_sandbox"}).status_code, 400)


@override_settings(**CONFIG)
class PayPalConcurrencyTests(TransactionTestCase):
    def test_concurrent_poll_and_webhook_commit_one_grant(self):
        account = Account.objects.create_user(username="race")
        plan = Plan.objects.create(code="race", name="Race", amount_minor=100, currency="USD", term_seconds=86400)
        intent = CheckoutRequest.objects.create(account=account, plan=plan, payment_provider=PaymentProvider.PAYPAL)
        api = FakePayPal()
        with patch("commerce.bridge.call", side_effect=FakeBridge()), patch("commerce.paypal_api.client", return_value=api):
            worker.prepare(intent.pk); paypal.process(intent.pk)
            api.capture(api.order_id, "external")
            PayPalOrder.objects.filter(pk=intent.pk).update(next_attempt=timezone.now())
            body = api.event()
            def receive(index):
                close_old_connections()
                try:return paypal.receive(body, HEADERS) if index else paypal.process(intent.pk)
                finally:close_old_connections()
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                list(pool.map(receive, range(6)))
        self.assertEqual(Payment.objects.count(), 1)
        self.assertEqual(ProvisionJob.objects.count(), 1)
        self.assertEqual(Entitlement.objects.get().issued_version, 1)


class PayPalMigrationTests(TransactionTestCase):
    def test_existing_simulator_ledger_survives_additive_migration(self):
        old = [("commerce", "0001_initial")]
        target = [("commerce", "0002_paypal_sandbox")]
        executor = MigrationExecutor(connection)
        try:
            executor.migrate(old)
            apps = executor.loader.project_state(old).apps
            account = apps.get_model("commerce", "Account").objects.create(username="before-paypal")
            plan = apps.get_model("commerce", "Plan").objects.create(code="old", name="Old", amount_minor=100, currency="USD", term_seconds=86400)
            intent = apps.get_model("commerce", "CheckoutRequest").objects.create(account=account, plan=plan)
            order = apps.get_model("commerce", "Order").objects.create(request=intent, account=account, state="ready", amount_minor=100,
                currency="USD", term_seconds=86400, reservation_id=uuid.uuid4().hex, reservation_expires=timezone.now())
            event_id, transaction_id = uuid.uuid4(), uuid.uuid4()
            event = apps.get_model("commerce", "PaymentEvent").objects.create(event_id=event_id, body_hash="a" * 64)
            apps.get_model("commerce", "Payment").objects.create(order=order, transaction_id=transaction_id, event=event,
                amount_minor=100, currency="USD", paid_at=timezone.now())
        finally:
            MigrationExecutor(connection).migrate(target)
        self.assertEqual(Order.objects.get(pk=order.pk).payment_provider, PaymentProvider.SIMULATOR)
        payment = Payment.objects.get(pk=order.pk)
        self.assertEqual(payment.transaction_id, transaction_id)
        self.assertEqual(payment.event_id, event_id)
        self.assertEqual(payment.provider, PaymentProvider.SIMULATOR)
        self.assertEqual(payment.amount_minor, 100)
        self.assertFalse(PayPalOrder.objects.exists())


class Response(io.BytesIO):
    status = 200


@override_settings(**CONFIG)
class PayPalTransportTests(SimpleTestCase):
    def test_preflight_only_checks_oauth_and_webhook_without_creating_payment(self):
        output = io.StringIO()
        with patch("commerce.paypal_api.client") as factory:
            api = factory.return_value
            api.request.return_value = {"url": CONFIG["PUBLIC_ORIGIN"] + "/webhooks/paypal/",
                                        "event_types": [{"name": "PAYMENT.CAPTURE.COMPLETED"}]}
            call_command("paypal_check", stdout=output)
            api.access_token.assert_called_once()
            api.request.assert_called_once_with("GET", "/v1/notifications/webhooks/TESTWEBHOOK1")
            api.create.assert_not_called(); api.capture.assert_not_called()
            api.request.return_value["url"] = "https://wrong.example/webhooks/paypal/"
            with self.assertRaises(CommandError):call_command("paypal_check", stdout=io.StringIO())
        self.assertNotIn(CONFIG["PAYPAL_CLIENT_SECRET"], output.getvalue())

    def test_exact_raw_webhook_bytes_are_forwarded_for_signature_verification(self):
        client = paypal_api.Client()
        body = b'{ "id" : "WH-TEST", "resource": {"amount": {"value": "1.00"}} }'
        responses = [Response(b'{"access_token":"token","expires_in":300}'), Response(b'{"verification_status":"SUCCESS"}')]
        with patch.object(client.opener, "open", side_effect=responses) as send:
            self.assertTrue(client.verify(body, HEADERS))
        request = send.call_args_list[-1].args[0]
        self.assertEqual(request.full_url, paypal_api.API_ORIGIN + "/v1/notifications/verify-webhook-signature")
        self.assertTrue(request.data.endswith(b'"webhook_event":' + body + b'}'))
        self.assertEqual(json.loads(request.data)["webhook_id"], "TESTWEBHOOK1")

    def test_request_id_oauth_refresh_and_sandbox_destination(self):
        client = paypal_api.Client()
        responses = [Response(b'{"access_token":"old","expires_in":300}'),
                     urllib.error.HTTPError(paypal_api.API_ORIGIN, 401, "Unauthorized", {}, io.BytesIO(b"{}")),
                     Response(b'{"access_token":"new","expires_in":300}'), Response(b'{"id":"5O190127TN364715T"}')]
        with patch.object(client.opener, "open", side_effect=responses) as send:
            client.capture("5O190127TN364715T", "same-request-id")
        requests = [call.args[0] for call in send.call_args_list]
        self.assertTrue(all(r.full_url.startswith(paypal_api.API_ORIGIN + "/") for r in requests))
        self.assertEqual(requests[1].get_header("Paypal-request-id"), "same-request-id")
        self.assertEqual(requests[3].get_header("Paypal-request-id"), "same-request-id")
        self.assertEqual(requests[3].get_header("Authorization"), "Bearer new")
        self.assertEqual(requests[1].data, requests[3].data)

    def test_redirects_oversized_responses_and_credential_leaks_are_rejected(self):
        client = paypal_api.Client()
        self.assertIsNone(paypal_api.NoRedirect().redirect_request(None, None, 307, "", {}, "https://elsewhere.example"))
        with patch.object(client.opener, "open", return_value=Response(b"x" * (paypal_api.MAX_RESPONSE + 1))), self.assertRaises(paypal_api.APIError):
            client.access_token()
        error = urllib.error.HTTPError(paypal_api.API_ORIGIN, 400, "", {}, io.BytesIO(b'{"name":"BAD_REQUEST", "message":"sandbox-test-secret"}'))
        with patch.object(client.opener, "open", side_effect=error), self.assertRaises(paypal_api.APIError) as caught:
            client.access_token()
        self.assertNotIn("sandbox-test-secret", str(caught.exception))

    def test_approval_url_never_points_to_live_or_unrelated_hosts(self):
        for url in ("https://www.paypal.com/checkoutnow?token=5O190127TN364715T", "https://evil.example/checkoutnow?token=5O190127TN364715T",
                    "https://www.sandbox.paypal.com@evil.example/checkoutnow?token=5O190127TN364715T", "javascript:alert(1)"):
            with self.subTest(url=url), self.assertRaises(PaymentError):
                paypal.approval_link({"links": [{"rel": "approve", "href": url}]}, "5O190127TN364715T")

    def test_money_never_rounds_or_accepts_another_currency(self):
        for value in ("1.001", "NaN", "-1.00", "1e2", 1.0):
            with self.subTest(value=value), self.assertRaises(PaymentError):paypal.money({"currency_code": "USD", "value": value})
        self.assertEqual(paypal.money({"currency_code": "USD", "value": "1.00"}), 100)
        self.assertEqual(paypal.money({"currency_code": "USD", "value": "1"}), 100)
        self.assertEqual(paypal.money({"currency_code": "USD", "value": "1.0"}), 100)

    def test_configuration_refuses_live_and_keeps_credentials_out_of_web(self):
        env = {"PORTAL_PAYPAL_ENABLED": "1", "PORTAL_PAYPAL_CLIENT_ID": "client", "PORTAL_PAYPAL_CLIENT_SECRET": "private-value",
               "PORTAL_PAYPAL_MERCHANT_ID": "TESTMERCHANT1"}
        self.assertEqual(configuration(env, "web")["PAYPAL_CLIENT_SECRET"], "")
        self.assertEqual(configuration(env, "worker")["PAYPAL_CLIENT_SECRET"], "private-value")
        for update in ({"PORTAL_PAYPAL_ENVIRONMENT": "live"}, {"PORTAL_PUBLIC_ORIGIN": "http://public.example"},
                       {"PORTAL_PUBLIC_ORIGIN": "https://example.test/path"}, {"PORTAL_PUBLIC_ORIGIN": "https://user:pass@example.test"}):
            with self.subTest(update=update), self.assertRaises(ImproperlyConfigured):configuration({**env, **update}, "worker")

    def test_private_config_loader_filters_secrets_and_rejects_public_files(self):
        from sandbox.paypal_environment import paypal_environment
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paypal.conf.private"
            path.write_text(json.dumps({"PORTAL_PAYPAL_ENABLED": "1", "PORTAL_PAYPAL_CLIENT_SECRET": "private-value"})); path.chmod(0o600)
            env = {"PORTAL_PAYPAL_CONFIG": str(path)}
            self.assertNotIn("PORTAL_PAYPAL_CLIENT_SECRET", paypal_environment("web", env))
            self.assertEqual(paypal_environment("worker", env)["PORTAL_PAYPAL_CLIENT_SECRET"], "private-value")
            path.chmod(0o644)
            with self.assertRaises(ValueError):paypal_environment("worker", env)
