import asyncio
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    import cryptography
except ImportError:
    cryptography = None

SOURCE = Path(__file__).resolve().parents[2] / 'scripts/webshare.py'
if cryptography:
    spec = importlib.util.spec_from_file_location('webshare_test_module', SOURCE)
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)


@unittest.skipUnless(cryptography, 'python3-cryptography required for Webshare')
class WebshareTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.key = os.urandom(32)
        self.calls = []
        self.bad_api = False
        self.failed_users = set()
        self.serial = 0
        self.config = {'api_key': 'test-api-token-never-publish', 'plan_id': 17, 'enabled': True, 'revision': 'initial'}
        self.persist()
        def fetch(key, path, params):
            self.calls.append((path, params))
            if self.bad_api:
                raise w.ProviderError('API Key 无效或没有访问此套餐的权限', 300)
            if path.endswith('/subscription/plan/'):
                return {'results': [{'id': 17, 'status': 'active', 'pool_filter': 'residential', 'bandwidth_limit': 10},
                    {'id': 18, 'status': 'active', 'proxy_subtype': 'isp'}, {'id': 19, 'status': 'cancelled', 'pool_filter': 'residential'}], 'next': None}
            if path.endswith('/proxy/list/'):
                return {'results': [{'username': 'testuser001-1234', 'password': 'test-password-private'}]}
            if path.endswith('/stats/aggregate/'):
                return {'bandwidth_total': 1234, 'requests_total': 10, 'requests_successful': 9, 'requests_failed': 1, 'secret-extra': key}
            raise AssertionError(path)
        async def check(username, password, country):
            self.assertEqual(password, 'test-password-private')
            if username in self.failed_users:
                raise w.ProviderError('住宅出口连接失败')
            self.serial += 1
            return {'exit_ip': '8.8.' + str(self.serial // 250) + '.' + str(self.serial % 250 + 1),
                'exit_country': country if country != 'ZZ' else 'DE', 'https_ms': self.serial, 'doh_ms': 12, 'last_success': w.stamp()}
        self.manager = w.Manager(self.directory, self.key, fetch, check)
        self.manager.desired = dict(self.config)
        await self.manager.sync(dict(self.config))

    def persist(self):
        w.atomic_write(self.directory / 'config.xgb', w.seal(self.config, self.key, w.CONFIG_CONTEXT))

    async def test_credentials_encryption_plan_filter_and_safe_report(self):
        m = self.manager
        await m.maintain_region('US')
        m.save()
        m.report()
        self.assertEqual([p['id'] for p in m.plans if p['eligible']], [17])
        self.assertEqual(m.active['credentials']['base'], 'testuser001')
        self.assertTrue(all(params.get('plan_id') == 17 for path, params in self.calls if '/subscription/' not in path))
        report = (self.directory / 'report.json').read_text()
        for secret in ('test-api-token', 'test-password', 'testuser001', 'secret-extra'):
            self.assertNotIn(secret, report)
            self.assertNotIn(secret.encode(), (self.directory / 'active.xgb').read_bytes())
        self.assertEqual((self.directory / 'active.xgb').stat().st_mode & 0o777, 0o600)
        restored = w.Manager(self.directory, self.key)
        self.assertEqual(restored.active['credentials'], m.active['credentials'])
        with self.assertRaises(Exception):
            w.unseal((self.directory / 'config.xgb').read_bytes(), os.urandom(32), w.CONFIG_CONTEXT)

    async def test_sticky_selection_failure_threshold_and_manual_rotation(self):
        m = self.manager
        await m.maintain_region('US')
        original = m.pools['US'][0]['username']
        await m.maintain_region('US')
        self.assertEqual(len(m.pools['US']), 4)
        self.assertEqual(m.pools['US'][0]['username'], original)
        m.pools['US'][0]['last_success'] = 1
        self.failed_users.add(original)
        for _ in range(2):
            await m.maintain_region('US')
            self.assertEqual(m.pools['US'][0]['username'], original)
        await m.maintain_region('US')
        self.assertNotEqual(m.pools['US'][0]['username'], original)
        previous = m.pools['US'][0]['username']
        m.force_rotate.add('US')
        await m.maintain_region('US')
        self.assertNotEqual(m.pools['US'][0]['username'], previous)
        self.assertEqual(m.events[0]['reason'], '手动更换会话')

    async def test_invalid_key_retains_working_state_and_backs_off(self):
        m = self.manager
        await m.maintain_region('US')
        original = dict(m.active)
        self.bad_api = True
        self.config.update(api_key='incorrect-api-key-value', revision='badkey')
        self.persist()
        m.desired = dict(self.config)
        await m.sync(dict(self.config))
        self.assertEqual(m.active, original)
        self.assertGreaterEqual(m.next_sync, w.stamp() + 299)
        self.assertTrue(m.enabled())
        self.config['enabled'] = False
        m.desired = self.config
        self.assertFalse(m.enabled())

    async def test_expired_sessions_removed_and_four_region_names(self):
        m = self.manager
        for country in w.REGIONS:
            await m.maintain_region(country)
            old = {p['username'] for p in m.pools[country]}
            for p in m.pools[country]:
                p['expires_at'] = 1
            await m.maintain_region(country)
            self.assertFalse(old & {p['username'] for p in m.pools[country]})
            for p in m.pools[country]:
                self.assertTrue(p['username'].startswith('testuser001-' + (country.lower() + '-' if country != 'ZZ' else '')))

    async def test_manual_rotation_uses_cached_plan_and_survives_restart(self):
        m = self.manager
        await m.maintain_region('US')
        before = len(self.calls)
        self.config.update(action='rotate', country='US', revision='manual-rotation')
        self.persist()
        task = asyncio.create_task(m.control_loop())
        try:
            await asyncio.sleep(.03)
            self.assertIn('US', m.force_rotate)
            self.assertEqual(len(self.calls), before)
            self.assertTrue(m.maintenance_wakeup.is_set())
            restored = w.Manager(self.directory, self.key)
            self.assertEqual(restored.processed_revision, 'manual-rotation')
        finally:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

    async def test_live_socks_relay_auth_tcp_and_udp_rejection(self):
        m = self.manager
        await m.maintain_region('US')
        received = []
        async def upstream(reader, writer):
            try:
                self.assertEqual(await reader.readexactly(3), b'\x05\x01\x02')
                writer.write(b'\x05\x02');await writer.drain()
                header = await reader.readexactly(2)
                username = await reader.readexactly(header[1])
                password = await reader.readexactly((await reader.readexactly(1))[0])
                received.append((username.decode(), password.decode()))
                writer.write(b'\x01\x00');await writer.drain()
                self.assertEqual(await reader.readexactly(10), b'\x05\x01\x00\x01\x08\x08\x08\x08\x01\xbb')
                writer.write(b'\x05\x00\x00\x01' + bytes(6));await writer.drain()
                data = await reader.readexactly(16)
                writer.write(data);await writer.drain()
            finally:
                writer.close();await writer.wait_closed()
        server = await asyncio.start_server(upstream, '127.0.0.1', 0)
        proxy = await asyncio.start_server(lambda r, s: m.handle(r, s, 'US'), '127.0.0.1', 0)
        original_open = asyncio.open_connection
        async def redirected(host, port, **kwargs):
            if host == 'p.webshare.io':
                return await original_open('127.0.0.1', server.sockets[0].getsockname()[1])
            return await original_open(host, port, **kwargs)
        try:
            with patch.object(w.asyncio, 'open_connection', redirected):
                reader, writer = await original_open('127.0.0.1', proxy.sockets[0].getsockname()[1])
                writer.write(b'\x05\x01\x00');await writer.drain()
                self.assertEqual(await reader.readexactly(2), b'\x05\x00')
                writer.write(b'\x05\x01\x00\x01\x08\x08\x08\x08\x01\xbb');await writer.drain()
                self.assertEqual(await reader.readexactly(10), b'\x05\x00\x00\x01' + bytes(6))
                writer.write(b'binary\x00payload!!');await writer.drain()
                self.assertEqual(await reader.readexactly(16), b'binary\x00payload!!')
                writer.close();await writer.wait_closed()
                self.assertEqual(received, [(m.pools['US'][0]['username'], 'test-password-private')])
                reader, writer = await original_open('127.0.0.1', proxy.sockets[0].getsockname()[1])
                writer.write(b'\x05\x01\x00');await writer.drain();await reader.readexactly(2)
                writer.write(b'\x05\x03\x00\x01');await writer.drain()
                self.assertEqual((await reader.readexactly(10))[1], 7)
                writer.close();await writer.wait_closed()
                self.assertEqual(len(received), 1)
        finally:
            proxy.close();server.close();await proxy.wait_closed();await server.wait_closed()


if __name__ == '__main__':
    unittest.main()
