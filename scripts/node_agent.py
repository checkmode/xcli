#!/usr/bin/env python3
"""Remote node controller. The Xray management API never leaves loopback."""
import argparse
import contextlib
import copy
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from node_ledger import Ledger, LedgerError

NODE_ID = re.compile(r'[0-9a-f]{32}\Z')
TOKEN = re.compile(r'[A-Za-z0-9_-]{43}\Z')
REVISION = re.compile(r'[0-9a-f]{64}\Z')
TAGS = ('reality', 'websocket', 'hysteria2')
MAX_RESPONSE = 256 * 1024


class AgentError(RuntimeError):
    pass


def panel_url(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise AgentError('Invalid panel URL')
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise AgentError('Invalid panel URL') from error
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment or (port is not None and not 1 <= port <= 65535)):
        raise AgentError('The panel URL must be an HTTPS origin without credentials or a path')
    return value.rstrip('/')


def desired_users(value):
    if not isinstance(value, dict) or set(value) != {'revision', 'users', 'lease_seconds', 'issued_at', 'ack'}:
        raise AgentError('Invalid panel response')
    if not isinstance(value['revision'], str) or not REVISION.fullmatch(value['revision']):
        raise AgentError('Invalid configuration revision')
    if type(value['lease_seconds']) is not int or not 10 <= value['lease_seconds'] <= 60:
        raise AgentError('Invalid access lease')
    if type(value['issued_at']) is not int or abs(time.time() - value['issued_at']) > 30:
        raise AgentError('Expired panel response or unsynchronized clock')
    users = value['users']
    if not isinstance(users, list) or len(users) > 500:
        raise AgentError('Invalid user list')
    result = {}
    for item in users:
        if not isinstance(item, dict) or set(item) != {'id', 'uuid', 'expires'}:
            raise AgentError('Invalid user')
        uid, credential, expires = item['id'], item['uuid'], item['expires']
        if (not isinstance(uid, str) or not NODE_ID.fullmatch(uid) or not isinstance(credential, str)
                or type(expires) is not int or expires < 0 or uid in result):
            raise AgentError('Invalid user')
        try:
            if str(uuid.UUID(credential)) != credential:
                raise ValueError
        except (ValueError, AttributeError) as error:
            raise AgentError('Invalid user credential') from error
        if not expires or expires > int(time.time()):
            result[uid] = {'id': uid, 'uuid': credential, 'expires': expires}
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AgentError('Panel redirects are not permitted')


def exchange(origin, node_id, token, payload, timeout=8):
    origin = panel_url(origin)
    if not NODE_ID.fullmatch(node_id) or not TOKEN.fullmatch(token):
        raise AgentError('Invalid node identity')
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(origin + '/api/nodes/sync', data=json.dumps(payload, separators=(',', ':')).encode(),
        headers={'Content-Type': 'application/json', 'Authorization': 'Xcli-Node ' + node_id + '.' + token}, method='POST')
    try:
        with client.open(request, timeout=timeout) as response:
            if response.status != 200 or response.headers.get_content_type() != 'application/json':
                raise AgentError('Panel rejected synchronization')
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise AgentError('Panel response too large')
            return json.loads(data)
    except (OSError, urllib.error.URLError, ValueError) as error:
        raise AgentError('Panel synchronization unavailable') from error


class XrayController:
    """Own one child process so systemd tears down Xray if the agent dies."""
    def __init__(self, binary, config_path, api='127.0.0.1:10085'):
        self.binary, self.config_path, self.api = str(binary), Path(config_path), api
        if not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', api):
            raise AgentError('Xray API must use IPv4 loopback')
        self.config = json.loads(self.config_path.read_text())
        if self.config.get('api', {}).get('listen') != api:
            raise AgentError('Core management API must listen only on configured loopback')
        inbound = self.config.get('inbounds', [])
        if not isinstance(inbound, list) or len(inbound) != len(TAGS) or {v.get('tag') for v in inbound} != set(TAGS):
            raise AgentError('Unexpected node core inbounds')
        for item in inbound:
            settings = item.get('settings', {})
            if settings.get('clients', []) or settings.get('users', []):
                raise AgentError('Persisted core configuration must not contain users')
        self.process = None
        self.generation = ''
        self.users = {}

    def command(self, *args, input_data=None, timeout=30):
        try:
            return subprocess.run([self.binary, 'api', args[0], '--server=' + self.api, *args[1:]], input=input_data,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=True).stdout
        except (OSError, subprocess.SubprocessError) as error:
            raise AgentError('Xray management API unavailable') from error

    def start(self):
        if self.process is not None:
            raise AgentError('Core already started')
        try:
            self.process = subprocess.Popen([self.binary, 'run', '-config', str(self.config_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True)
        except OSError as error:
            raise AgentError('Xray core failed to start') from error
        self.generation = uuid.uuid4().hex
        self.users = {}
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.process = None
                raise AgentError('Xray core exited during startup')
            try:
                self.command('inboundusercount', '-tag=reality', '--timeout=1', timeout=2)
                return
            except AgentError:
                time.sleep(.2)
        self.stop()
        raise AgentError('Xray core did not become ready')

    def stop(self):
        if self.process is not None:
            process, self.process = self.process, None
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        self.users = {}
        self.generation = ''

    def counters(self):
        if self.process is None or self.process.poll() is not None:
            raise AgentError('Xray core is not running')
        try:
            value = json.loads(self.command('statsquery', '-pattern=user>>>', '--timeout=3', timeout=5))
        except ValueError as error:
            raise AgentError('Invalid Xray statistics') from error
        if not isinstance(value, dict) or not isinstance(value.get('stat', []), list):
            raise AgentError('Invalid Xray statistics')
        return value.get('stat', [])

    def apply(self, users):
        if self.process is None or self.process.poll() is not None:
            raise AgentError('Xray core is not running')
        remove = any(uid not in users or users[uid]['uuid'] != old['uuid'] for uid, old in self.users.items())
        if remove:
            # Xray user removal does not necessarily terminate established streams.
            self.stop()
            self.start()
        additions = [entry for uid, entry in users.items() if uid not in self.users]
        if not additions:
            self.users = copy.deepcopy(users)
            return
        inbound = []
        for original in self.config['inbounds']:
            item = copy.deepcopy(original)
            tag = item['tag']
            entries = []
            for user in additions:
                email = user['id'] + '.' + user['uuid'][:8] + '@' + tag
                if tag == 'hysteria2':
                    entries.append({'email': email, 'auth': user['uuid']})
                else:
                    entry = {'email': email, 'id': user['uuid']}
                    if tag == 'reality':
                        entry['flow'] = 'xtls-rprx-vision'
                    entries.append(entry)
            item['settings']['clients'] = entries
            inbound.append(item)
        try:
            output = self.command('adu', '--timeout=30', 'stdin:', input_data=json.dumps({'inbounds': inbound}).encode(), timeout=35)
            expected = len(additions) * len(TAGS)
            if ('Added ' + str(expected) + ' user(s) in total.').encode() not in output:
                raise AgentError('Xray did not accept all user entries')
            self.users = copy.deepcopy(users)
        except BaseException:
            # Partial additions must not continue serving after a failed reconciliation.
            self.stop()
            raise


class NodeAgent:
    def __init__(self, node_id, token, origin, ledger, core, sender=exchange, monotonic=time.monotonic):
        if not NODE_ID.fullmatch(node_id) or not TOKEN.fullmatch(token):
            raise AgentError('Invalid node identity')
        self.node_id, self.token, self.origin = node_id, token, panel_url(origin)
        self.ledger, self.core, self.sender, self.monotonic = ledger, core, sender, monotonic
        self.lock = threading.RLock()
        self.lease_until = 0
        self.revision = ''

    def sample(self):
        if self.core.process is not None:
            self.ledger.record(self.core.generation, self.core.counters())

    def check_lease(self):
        with self.lock:
            if self.core.process is not None:
                self.sample()
            if self.core.users and (self.monotonic() >= self.lease_until or any(
                    user['expires'] and user['expires'] <= int(time.time()) for user in self.core.users.values())):
                self.core.apply({})
                self.revision = ''
                self.lease_until = 0

    def watchdog_tick(self):
        if self.lock.acquire(timeout=.25):
            try:
                self.check_lease()
            except (AgentError, LedgerError, OSError, sqlite3.Error):
                self.core.stop()
                self.revision = ''
                self.lease_until = 0
            finally:
                self.lock.release()
        elif self.lease_until and self.monotonic() >= self.lease_until:
            # A stalled RPC must not hold the lock beyond the authorization lease.
            process = self.core.process
            if process is not None:
                with contextlib.suppress(OSError):
                    if process.poll() is None:
                        process.terminate()

    def synchronize(self):
        with self.lock:
            if self.core.process is None:
                self.core.start()
            self.sample()
            pending = self.ledger.pending()
            payload = {'revision': self.revision, 'counters': pending}
        response = self.sender(self.origin, self.node_id, self.token, payload)
        users = desired_users(response)
        if response['ack'] != pending:
            raise AgentError('Panel acknowledgement differs from submitted accounting')
        with self.lock:
            # A delayed response cannot extend a lease issued in the past.
            remaining = response['lease_seconds'] - max(0, time.time() - response['issued_at'])
            if remaining <= 0:
                raise AgentError('Panel access lease expired in transit')
            # Snapshot before any revocation, since that restarts the core.
            self.sample()
            self.ledger.acknowledge(response['ack'])
            # The watchdog can terminate the process if reconciliation stalls.
            self.lease_until = self.monotonic() + remaining
            try:
                self.core.apply(users)
            except BaseException:
                self.core.stop()
                self.revision = ''
                self.lease_until = 0
                raise
            self.revision = response['revision']
            remaining = response['lease_seconds'] - max(0, time.time() - response['issued_at'])
            if remaining <= 0:
                self.core.apply({})
                self.revision = ''
                self.lease_until = 0
                raise AgentError('Panel access lease expired during application')
            self.lease_until = self.monotonic() + remaining

    def stop(self):
        with self.lock:
            try:
                self.sample()
            finally:
                self.core.stop()
                self.revision = ''
                self.lease_until = 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--core-config', type=Path, required=True)
    parser.add_argument('--xray', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    config = json.loads(args.config.read_text())
    if set(config) != {'node_id', 'token', 'panel'}:
        raise AgentError('Invalid node configuration')
    args.state.mkdir(mode=0o700, parents=True, exist_ok=True)
    ledger = Ledger(args.state / 'traffic.sqlite')
    agent = NodeAgent(config['node_id'], config['token'], config['panel'], ledger,
                      XrayController(args.xray, args.core_config))
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    def watchdog():
        while not stopping.wait(1):
            agent.watchdog_tick()
    guard = threading.Thread(target=watchdog, daemon=True)
    guard.start()
    try:
        while not stopping.is_set():
            try:
                agent.synchronize()
            except (AgentError, LedgerError, OSError, sqlite3.Error):
                print('节点同步暂不可用；权限租约到期后停止接入', file=sys.stderr, flush=True)
            stopping.wait(5)
    finally:
        stopping.set()
        guard.join(timeout=10)
        try:
            agent.stop()
        finally:
            ledger.close()
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (AgentError, LedgerError, OSError, sqlite3.Error, ValueError):
        print('节点服务启动失败，请检查本机配置和日志', file=sys.stderr)
        raise SystemExit(1)
