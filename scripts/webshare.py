#!/usr/bin/env python3
"""Bounded Webshare control plane and four loopback-only, TCP-only SOCKS gateways."""
import argparse
import asyncio
import base64
import contextlib
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REGIONS = {'US': '美国', 'JP': '日本', 'SG': '新加坡', 'ZZ': '全球'}
PORTS = dict(zip(REGIONS, range(10120, 10124)))
CONFIG_CONTEXT = b'xcli:webshare:config:v1'
ACTIVE_CONTEXT = b'xcli:webshare:active:v1'
SESSION_AGE = 1800
PROBE_AGE = 120
STANDBY_COUNT = 3


def stamp():
    return int(time.time())


def seal(value, key, context):
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(key).encrypt(nonce, json.dumps(value, ensure_ascii=False).encode(), context)
    return b'XGB1' + nonce + encrypted[-16:] + encrypted[:-16]


def unseal(value, key, context):
    if len(value) < 32 or value[:4] != b'XGB1':
        raise ValueError('Invalid encrypted state')
    return json.loads(AESGCM(key).decrypt(value[4:16], value[32:] + value[16:32], context))


def atomic_write(path, data):
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8))
    try:
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class ProviderError(Exception):
    def __init__(self, message, retry=60):
        super().__init__(message)
        self.retry = retry


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api_get(key, path, parameters=None):
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,256}', key):
        raise ProviderError('API Key 格式不正确')
    if path not in ('/api/v2/subscription/plan/', '/api/v2/proxy/list/', '/api/v3/proxy/config', '/api/v2/stats/aggregate/'):
        raise ValueError('Unexpected API resource')
    url = 'https://proxy.webshare.io' + path + '?' + urllib.parse.urlencode(parameters or {})
    request = urllib.request.Request(url, headers={'Authorization': 'Token ' + key, 'Accept': 'application/json', 'User-Agent': 'xcli-webshare/1'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=12) as response:
            data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise ProviderError('Webshare 返回的数据过大')
            return json.loads(data)
    except urllib.error.HTTPError as error:
        if error.code == 429:
            raise ProviderError('Webshare 请求限流，稍后自动重试', 90) from None
        if error.code in (401, 403):
            raise ProviderError('API Key 无效或没有访问此套餐的权限', 300) from None
        raise ProviderError('Webshare 接口暂不可用（HTTP %s）' % error.code) from None
    except (OSError, ValueError, urllib.error.URLError):
        raise ProviderError('无法读取 Webshare，请检查网络或稍后重试') from None


def plans_from_response(value):
    if not isinstance(value, dict) or not isinstance(value.get('results'), list):
        raise ProviderError('Webshare 套餐数据格式不支持')
    plans = []
    for row in value['results']:
        if not isinstance(row, dict) or type(row.get('id')) is not int:
            continue
        eligible = row.get('status') == 'active' and (row.get('pool_filter') == 'residential' or row.get('proxy_subtype') == 'residential')
        plans.append({'id': row['id'], 'status': str(row.get('status', 'unknown'))[:40],
            'pool_filter': str(row.get('pool_filter', ''))[:40], 'proxy_subtype': str(row.get('proxy_subtype', ''))[:40],
            'bandwidth_limit': row.get('bandwidth_limit') if type(row.get('bandwidth_limit')) in (int, float) else None,
            'eligible': eligible, 'label': ('动态住宅' if eligible else '不可用于动态住宅池') + ' · #' + str(row['id'])})
    return plans


def credentials(value):
    rows = value.get('results', []) if isinstance(value, dict) else []
    if not rows:
        raise ProviderError('该套餐没有返回可用的住宅入口')
    user, password = rows[0].get('username'), rows[0].get('password')
    if not isinstance(user, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,64}(?:-[A-Za-z0-9_-]+)?', user):
        raise ProviderError('Webshare 代理用户名格式不支持')
    if not isinstance(password, str) or not 1 <= len(password.encode()) <= 255 or any(ord(c) < 32 for c in password):
        raise ProviderError('Webshare 没有返回有效的代理密码')
    return {'base': user.split('-')[0], 'password': password}


def session_username(base, country, identifier):
    if country not in REGIONS or not str(identifier).isdigit():
        raise ValueError('Invalid session')
    return base + ('-' + country.lower() if country != 'ZZ' else '') + '-' + str(identifier)


async def curl_proxy(user, password, url, accept=None):
    def quote(value):
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
    configuration = 'proxy = "socks5h://p.webshare.io:80"\nproxy-user = ' + quote(user + ':' + password) + '\nurl = ' + quote(url) + '\n'
    if accept:
        configuration += 'header = ' + quote('Accept: ' + accept) + '\n'
    process = await asyncio.create_subprocess_exec('curl', '-q', '-4', '-fsS', '--noproxy', '', '--max-time', '14', '--connect-timeout', '8',
        '--max-filesize', '32768', '--config', '-', stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        output, _ = await asyncio.wait_for(process.communicate(configuration.encode()), 17)
        if process.returncode or len(output) > 32768:
            raise ProviderError('住宅出口连接失败')
        return output
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


async def probe(user, password, country):
    started = time.monotonic()
    data = await curl_proxy(user, password, 'https://www.cloudflare.com/cdn-cgi/trace')
    fields = dict(line.split('=', 1) for line in data.decode('ascii', errors='ignore').splitlines() if '=' in line)
    try:
        address = ipaddress.ip_address(fields.get('ip', ''))
        if not address.is_global or address.is_multicast or (country != 'ZZ' and fields.get('loc') != country):
            raise ValueError()
    except ValueError:
        raise ProviderError('出口 IP 或国家验证失败') from None
    https_ms = round((time.monotonic() - started) * 1000)
    packet = b'XG\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
    started = time.monotonic()
    answer = await curl_proxy(user, password, 'https://1.1.1.1/dns-query?dns=' + base64.urlsafe_b64encode(packet).decode().rstrip('='), 'application/dns-message')
    if len(answer) < 12 or answer[:2] != b'XG' or not answer[2] & 128 or answer[3] & 15 or not int.from_bytes(answer[6:8], 'big'):
        raise ProviderError('住宅出口 DoH 验证失败')
    return {'exit_ip': str(address), 'exit_country': fields.get('loc', ''), 'https_ms': https_ms,
        'doh_ms': round((time.monotonic() - started) * 1000), 'last_success': stamp()}


class Manager:
    def __init__(self, directory, key, fetch=api_get, check=probe):
        self.directory, self.key, self.fetch, self.check = directory, key, fetch, check
        self.active = {'enabled': False, 'plan_id': 0}
        self.desired = {}
        self.pools = {country: [] for country in REGIONS}
        self.events, self.plans, self.usage = [], [], {}
        self.sync_error = self.usage_error = ''
        self.last_sync = self.last_attempt = self.next_sync = 0
        self.processed_revision = ''
        self.epoch = 0
        self.semaphore = asyncio.Semaphore(2)
        self.connections = set()
        self.upstreams = set()
        self.force_rotate = set()
        self.maintenance_wakeup = asyncio.Event()
        self.cooldown = {country: 0 for country in REGIONS}
        self.failures = {country: 0 for country in REGIONS}
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with contextlib.suppress(OSError, ValueError, KeyError):
            saved = unseal((directory / 'active.xgb').read_bytes(), key, ACTIVE_CONTEXT)
            self.active = saved['active']
            self.processed_revision = saved.get('processed_revision', '')
            self.plans = saved.get('plans', [])
            self.pools = {c: [s for s in saved.get('pools', {}).get(c, []) if s.get('expires_at', 0) > stamp()] for c in REGIONS}

    def save(self):
        atomic_write(self.directory / 'active.xgb', seal({'active': self.active, 'plans': self.plans,
            'pools': self.pools, 'processed_revision': self.processed_revision}, self.key, ACTIVE_CONTEXT))

    def enabled(self):
        return bool(self.desired.get('enabled') and self.active.get('enabled'))

    def report(self):
        pools = []
        for country, sessions in self.pools.items():
            live = sessions[0] if sessions else {}
            recent = live.get('last_success', 0) > stamp() - PROBE_AGE * 2 and live.get('expires_at', 0) > stamp()
            value = {'country': country, 'label': '动态住宅 · ' + REGIONS[country], 'status': 'disabled' if not self.enabled() else 'healthy' if recent else 'unavailable',
                'standby': max(0, len(sessions) - 1), 'failures': self.failures[country], 'error': '' if recent else '等待可用会话'}
            value.update({key: live[key] for key in ('exit_ip', 'exit_country', 'https_ms', 'doh_ms', 'last_success', 'selected_at', 'expires_at') if key in live})
            pools.append(value)
        healthy = sum(p['status'] == 'healthy' for p in pools)
        status = 'healthy' if healthy == 4 else 'degraded' if self.enabled() else 'disabled' if self.active.get('api_key') else 'unconfigured'
        value = {'updated': stamp(), 'status': status, 'message': '四个动态入口可用' if healthy == 4 else '部分区域正在寻找可用出口' if self.enabled() else '选择套餐并启用动态住宅池',
            'enabled': self.enabled(), 'active_plan_id': self.active.get('plan_id', 0), 'revision': self.processed_revision,
            'last_sync': self.last_sync, 'last_attempt': self.last_attempt, 'next_sync': self.next_sync,
            'sync_error': self.sync_error, 'usage_error': self.usage_error, 'plans': self.plans, 'pools': pools, 'events': self.events[:20], **self.usage}
        atomic_write(self.directory / 'report.json', json.dumps(value, ensure_ascii=False).encode())

    def read_desired(self):
        try:
            return unseal((self.directory / 'config.xgb').read_bytes(), self.key, CONFIG_CONTEXT)
        except FileNotFoundError:
            return {'enabled': False, 'api_key': '', 'revision': ''}

    async def sync(self, desired):
        self.last_attempt = stamp()
        key, plan_id = desired.get('api_key', ''), desired.get('plan_id', 0)
        try:
            plans = []
            for page in range(1, 11):
                response = await asyncio.to_thread(self.fetch, key, '/api/v2/subscription/plan/', {'page': page, 'page_size': 100})
                plans.extend(plans_from_response(response))
                if not response.get('next'):
                    break
            else:
                raise ProviderError('套餐数量超出当前支持范围')
            self.plans = plans[:100]
            next_active = dict(desired)
            if plan_id:
                selected = next((p for p in plans if p['id'] == plan_id and p['eligible']), None)
                if not selected:
                    if self.active.get('api_key') == key and self.active.get('plan_id') == plan_id:
                        self.active['enabled'] = False
                    raise ProviderError('所选套餐不是有效的动态住宅套餐')
                rows = await asyncio.to_thread(self.fetch, key, '/api/v2/proxy/list/', {'mode': 'backbone', 'plan_id': plan_id, 'page': 1, 'page_size': 1})
                next_active['credentials'] = credentials(rows)
            # Reject stale completions if the user changed settings while the API was in flight.
            if self.read_desired().get('revision') != desired.get('revision'):
                return
            changed = any(self.active.get(k) != next_active.get(k) for k in ('plan_id', 'credentials'))
            self.active = next_active
            if changed:
                self.epoch += 1
                self.pools = {country: [] for country in REGIONS}
            if desired.get('action') == 'rotate' and desired.get('revision') != self.processed_revision:
                self.force_rotate.add(desired['country'])
            self.processed_revision = desired.get('revision', '')
            self.last_sync, self.next_sync, self.sync_error = stamp(), stamp() + 300, ''
            self.save()
            self.maintenance_wakeup.set()
            if plan_id:
                await self.update_usage(key, plan_id)
        except ProviderError as error:
            self.sync_error = str(error)
            self.next_sync = stamp() + error.retry
            self.processed_revision = desired.get('revision', '')
        except Exception:
            self.sync_error = 'Webshare 返回格式不支持，稍后自动重试'
            self.next_sync = stamp() + 60
            self.processed_revision = desired.get('revision', '')

    async def update_usage(self, key, plan_id):
        def iso(value):
            return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()
        try:
            usage = await asyncio.to_thread(self.fetch, key, '/api/v2/stats/aggregate/', {'plan_id': plan_id, 'timestamp__gte': iso(stamp() - 86400), 'timestamp__lte': iso(stamp())})
            self.usage = {k: usage[k] for k in ('bandwidth_total', 'requests_total', 'requests_successful', 'requests_failed') if type(usage.get(k)) is int and usage[k] >= 0}
            self.usage['usage_updated'], self.usage_error = stamp(), ''
        except ProviderError as error:
            self.usage_error = str(error)
            self.next_sync = max(self.next_sync, stamp() + error.retry)
        except Exception:
            self.usage_error = 'Webshare 用量格式不支持，稍后自动重试'

    async def checked(self, session, country, credential):
        async with self.semaphore:
            result = await self.check(session['username'], credential['password'], country)
        return {**session, **result, 'failures': 0}

    async def maintain_region(self, country):
        if not self.enabled() or 'credentials' not in self.active:
            return
        epoch, credential = self.epoch, dict(self.active['credentials'])
        old = self.pools[country][0] if self.pools[country] else None
        sessions = [s for s in self.pools[country] if s['expires_at'] > stamp()]
        forced = country in self.force_rotate
        if forced:
            self.force_rotate.discard(country)
            sessions = [s for s in sessions if old is None or s['username'] != old['username']]
        checked = []
        for session in sessions:
            if session.get('last_success', 0) <= stamp() - PROBE_AGE:
                try:
                    session = await self.checked(session, country, credential)
                except ProviderError:
                    session = {**session, 'failures': session.get('failures', 0) + 1}
                    if session['failures'] >= 3:
                        continue
            checked.append(session)
        sessions = checked
        if len(sessions) < STANDBY_COUNT + 1 and stamp() >= self.cooldown[country]:
            # At most two new sessions per region per pass; never enumerate an exported 20,000-row list.
            for _ in range(min(2, STANDBY_COUNT + 1 - len(sessions))):
                identifier = str(secrets.randbelow(2**48))
                candidate = {'username': session_username(credential['base'], country, identifier), 'expires_at': stamp() + SESSION_AGE}
                try:
                    candidate = await self.checked(candidate, country, credential)
                    if candidate['exit_ip'] not in {s.get('exit_ip') for s in sessions}:
                        sessions.append(candidate)
                except ProviderError:
                    self.cooldown[country] = stamp() + 60
        if epoch != self.epoch or not self.enabled():
            return
        # Keep a healthy current session even when a newer candidate has lower latency.
        if old and any(s['username'] == old['username'] and s.get('failures', 0) < 3 for s in sessions) and not forced:
            sessions.sort(key=lambda s: (s['username'] != old['username'], s.get('failures', 0), s.get('https_ms', 99999)))
        else:
            sessions.sort(key=lambda s: (s.get('failures', 0), s.get('https_ms', 99999)))
        if sessions and (old is None or sessions[0]['username'] != old['username']):
            sessions[0]['selected_at'] = stamp()
            reason = '手动更换会话' if forced else '首次选定出口' if old is None else '会话到期' if old['expires_at'] <= stamp() else '出口故障切换'
            self.events.insert(0, {'country': country, 'ts': stamp(), 'reason': reason})
            self.events = self.events[:20]
        if sessions and old and sessions[0]['username'] == old['username'] and sessions[0].get('exit_ip') != old.get('exit_ip'):
            self.events.insert(0, {'country': country, 'ts': stamp(), 'reason': '供应商调整了当前会话的出口 IP'})
            self.events = self.events[:20]
        self.pools[country] = sessions
        self.failures[country] = sessions[0].get('failures', 0) if sessions else 3

    async def maintenance_loop(self):
        while True:
            try:
                await asyncio.gather(*(self.maintain_region(country) for country in REGIONS))
                if self.enabled():
                    self.save()
            except Exception:
                # Exception details can contain provider credentials; never log them.
                self.sync_error = '池维护暂时失败，将自动重试'
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self.maintenance_wakeup.wait(), 20)
            self.maintenance_wakeup.clear()

    async def control_loop(self):
        syncing = None
        try:
            while True:
                try:
                    desired = self.read_desired()
                    self.desired = desired
                    if not self.enabled():
                        for writer in tuple(self.connections | self.upstreams):
                            writer.close()
                    if not desired.get('api_key') and (self.active.get('api_key') or any(self.pools.values()) or desired.get('revision', '') != self.processed_revision):
                        if syncing and not syncing.done():
                            syncing.cancel()
                        self.active = {'enabled': False, 'plan_id': 0}
                        self.pools = {country: [] for country in REGIONS}
                        self.plans, self.usage, self.sync_error = [], {}, ''
                        self.processed_revision = desired.get('revision', '')
                        self.epoch += 1
                        self.save()
                    elif (desired.get('action') == 'rotate' and self.enabled() and
                          desired.get('revision') != self.processed_revision and
                          all(desired.get(k) == self.active.get(k) for k in ('api_key', 'plan_id'))):
                        self.force_rotate.add(desired['country'])
                        self.processed_revision = desired['revision']
                        self.save()
                        self.maintenance_wakeup.set()
                    elif desired.get('api_key') and (not syncing or syncing.done()) and (desired.get('revision') != self.processed_revision or stamp() >= self.next_sync):
                        syncing = asyncio.create_task(self.sync(dict(desired)))
                    self.report()
                except Exception:
                    self.desired = {'enabled': False}
                    for writer in tuple(self.connections | self.upstreams):
                        writer.close()
                    self.sync_error = '无法读取池配置，请重新保存设置'
                    self.report()
                await asyncio.sleep(3)
        finally:
            if syncing:
                syncing.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await syncing

    async def handle(self, reader, writer, country):
        upstream = None
        try:
            if len(self.connections) >= 128:
                return
            self.connections.add(writer)
            async with asyncio.timeout(12):
                version, count = await reader.readexactly(2)
                methods = await reader.readexactly(count)
                if version != 5 or 0 not in methods:
                    writer.write(b'\x05\xff')
                    await writer.drain()
                    return
                writer.write(b'\x05\x00')
                await writer.drain()
                version, command, reserved, kind = await reader.readexactly(4)
                if version != 5 or command != 1 or reserved != 0:
                    writer.write(b'\x05\x07\x00\x01' + bytes(6))
                    await writer.drain()
                    return
                if kind == 1:
                    address = await reader.readexactly(4)
                    if not ipaddress.ip_address(address).is_global:
                        raise ProviderError('Destination rejected')
                elif kind == 4:
                    address = await reader.readexactly(16)
                    if not ipaddress.ip_address(address).is_global:
                        raise ProviderError('Destination rejected')
                elif kind == 3:
                    length = await reader.readexactly(1)
                    address = length + await reader.readexactly(length[0])
                    if not length[0] or not re.fullmatch(rb'[A-Za-z0-9._-]+', address[1:]):
                        raise ProviderError('Destination rejected')
                else:
                    raise ProviderError('Address type rejected')
                port = await reader.readexactly(2)
                if port == bytes(2) or not self.enabled():
                    raise ProviderError('Pool disabled')
                sessions = self.pools[country]
                if not sessions or sessions[0]['expires_at'] <= stamp() or sessions[0].get('last_success', 0) < stamp() - PROBE_AGE * 3:
                    raise ProviderError('No healthy session')
                selected, credential = dict(sessions[0]), dict(self.active['credentials'])
                source, upstream = await asyncio.open_connection('p.webshare.io', 80, family=socket.AF_INET)
                self.upstreams.add(upstream)
                upstream.write(b'\x05\x01\x02')
                await upstream.drain()
                if await source.readexactly(2) != b'\x05\x02':
                    raise ProviderError('Proxy authentication unavailable')
                user, password = selected['username'].encode(), credential['password'].encode()
                upstream.write(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
                await upstream.drain()
                if await source.readexactly(2) != b'\x01\x00':
                    raise ProviderError('Proxy authentication failed')
                upstream.write(b'\x05\x01\x00' + bytes([kind]) + address + port)
                await upstream.drain()
                header = await source.readexactly(4)
                if header[0] != 5 or header[1] != 0:
                    raise ProviderError('Proxy connection failed')
                if header[3] == 1:
                    await source.readexactly(6)
                elif header[3] == 4:
                    await source.readexactly(18)
                elif header[3] == 3:
                    await source.readexactly((await source.readexactly(1))[0] + 2)
                else:
                    raise ProviderError('Proxy reply invalid')
                writer.write(b'\x05\x00\x00\x01' + bytes(6))
                await writer.drain()
            async def copy(source, destination):
                while data := await asyncio.wait_for(source.read(65536), 600):
                    destination.write(data)
                    await destination.drain()
                if destination.can_write_eof():
                    destination.write_eof()
            tasks = [asyncio.create_task(copy(reader, upstream)), asyncio.create_task(copy(source, writer))]
            try:
                async with asyncio.timeout(86400):
                    await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, ValueError, ProviderError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            with contextlib.suppress(OSError):
                writer.write(b'\x05\x01\x00\x01' + bytes(6))
                await writer.drain()
        finally:
            self.connections.discard(writer)
            self.upstreams.discard(upstream)
            for stream in (writer, upstream):
                if stream:
                    stream.close()
                    with contextlib.suppress(OSError, asyncio.TimeoutError):
                        await asyncio.wait_for(stream.wait_closed(), 2)


async def main(args):
    manager = Manager(args.state, args.key.read_bytes())
    servers = []
    try:
        for country, port in PORTS.items():
            servers.append(await asyncio.start_server(lambda r, w, c=country: manager.handle(r, w, c), '127.0.0.1', port, limit=65536))
        await asyncio.gather(manager.control_loop(), manager.maintenance_loop())
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', type=Path, default=Path('/var/lib/xray-gateway/webshare'))
    parser.add_argument('--key', type=Path, default=Path('/etc/xray-gateway/security.key'))
    args = parser.parse_args()
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        pass
