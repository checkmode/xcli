"""Real PostgreSQL + real C++ controller; no production state or external payment service."""
import contextlib
import json
import os
import pathlib
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
from unittest import skipUnless

from django.test import TransactionTestCase, override_settings

from . import payments, worker
from .models import Account, CheckoutRequest, Entitlement, Order, Payment, Plan, ProvisionJob, SandboxCharge, SandboxPaymentRequest


@skipUnless(os.environ.get("XG_TEST_BINARY"), "Requires the compiled C++ sandbox controller")
@override_settings(ROLE="owner", SANDBOX_SIGNING_KEY="real-bridge-local-test-key-" * 4)
class GatewayIntegrationTests(TransactionTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="xportal-real-gateway-")
        self.addCleanup(self.directory.cleanup)
        root = pathlib.Path(self.directory.name)
        settings = root / "settings.json"
        settings.write_text(json.dumps({"domain": "sandbox.invalid", "public_ip": "192.0.2.1", "origin": "https://sandbox.invalid",
            "reality_sni": "example.com", "reality_public": "p" * 43, "short_id": "aabbccdd", "ws_path": "/sandbox"}))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.path = root / "provision.sock"
        self.state = root / "state"
        self.process = subprocess.Popen([os.environ["XG_TEST_BINARY"], "--offline", "--no-auto-backup", "--settings", str(settings),
            "--state", str(self.state), "--port", str(self.port), "--provision-socket", str(self.path), "--provision-uid", str(os.getuid())], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_controller)
        for _ in range(100):
            self.assertIsNone(self.process.poll())
            if self.path.exists():
                break
            time.sleep(.05)
        else:
            self.fail("Local provisioning socket not ready")
        self.setting = override_settings(PROVISION_SOCKET=str(self.path))
        self.setting.enable()
        self.addCleanup(self.setting.disable)
        self.account = Account.objects.create_user(username="real-bridge")
        self.plan = Plan.objects.create(code="integration", name="Integration", amount_minor=100, currency="USD", term_seconds=30 * 86400)

    def stop_controller(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def test_verified_payment_survives_process_loss_after_real_gateway_commit(self):
        intent = CheckoutRequest.objects.create(account=self.account, plan=self.plan)
        worker.prepare(intent.pk)
        order = Order.objects.get(pk=intent.pk)
        SandboxPaymentRequest.objects.create(order=order, channel="card")
        worker.simulate_charge(order.pk)
        worker.deliver_charge(order.pk, payments.receive)

        class ProcessLoss(BaseException):
            pass

        def crash():
            raise ProcessLoss()

        with self.assertRaises(ProcessLoss):
            worker.provision(order.pk, after_grant=crash)
        with contextlib.closing(sqlite3.connect(f"file:{self.state / 'gateway.sqlite'}?mode=ro", uri=True)) as db:
            first = db.execute("SELECT id,uuid,token,expires FROM users WHERE deleted=0").fetchall()
            self.assertEqual(len(first), 1)
        self.assertFalse(ProvisionJob.objects.get(pk=order.pk).done)
        worker.provision(order.pk)
        with contextlib.closing(sqlite3.connect(f"file:{self.state / 'gateway.sqlite'}?mode=ro", uri=True)) as db:
            self.assertEqual(db.execute("SELECT id,uuid,token,expires FROM users WHERE deleted=0").fetchall(), first)
        self.assertEqual(Entitlement.objects.get(account=self.account).version, 1)
        self.assertEqual(Payment.objects.count(), 1)
        self.assertTrue(ProvisionJob.objects.get(pk=order.pk).done)
        self.assertEqual(Order.objects.get(pk=order.pk).state, Order.State.READY)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{self.port}/s/{first[0][2]}", timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertGreater(len(response.read()), 100)

    def test_controller_restart_recovers_committed_idempotency_history(self):
        intent = CheckoutRequest.objects.create(account=self.account, plan=self.plan)
        worker.prepare(intent.pk)
        order = Order.objects.get(pk=intent.pk)
        worker.simulate_charge(order.pk)
        worker.deliver_charge(order.pk, payments.receive)

        class ProcessLoss(BaseException):
            pass

        def crash():
            raise ProcessLoss()

        with self.assertRaises(ProcessLoss):
            worker.provision(order.pk, after_grant=crash)
        args = self.process.args
        self.process.kill()
        self.process.wait()
        self.assertTrue(self.path.exists())
        self.process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            self.assertIsNone(self.process.poll())
            try:
                worker.provision(order.pk)
                if ProvisionJob.objects.get(pk=order.pk).done:
                    break
            except OSError:
                pass
            # A transient connection failure schedules a retry; simulate its due time.
            from django.utils import timezone
            ProvisionJob.objects.filter(pk=order.pk).update(available_at=timezone.now())
            time.sleep(.05)
        self.assertTrue(ProvisionJob.objects.get(pk=order.pk).done)
        self.assertEqual(Entitlement.objects.get(account=self.account).version, 1)
