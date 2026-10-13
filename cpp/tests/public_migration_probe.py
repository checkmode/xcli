"""Compare public behavior across migration; keep all credentials in a private file."""
import argparse
import hashlib
import json
import os
import pathlib
import urllib.error
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'verify'])
    parser.add_argument('--snapshot', type=pathlib.Path, required=True)
    parser.add_argument('--admin', type=pathlib.Path)
    parser.add_argument('--base', default='https://gateway.example.com')
    parser.add_argument('--allow-offline', action='store_true')
    parser.add_argument('--allow-frontend-change', action='store_true')
    args = parser.parse_args()
    origin = args.base.rstrip('/')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token = ''
    def request(path, data=None):
        headers = {'Origin': origin, 'Host': urllib.parse.urlsplit(origin).netloc}
        if token:
            headers['Cookie'] = 'xg_session=' + token
        if data is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(data).encode()
        req = urllib.request.Request(args.base.rstrip('/') + path, data=data, headers=headers)
        try:
            with opener.open(req, timeout=20) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()
    def get_json(path):
        status, _, content = request(path)
        if status != 200:
            raise RuntimeError('Authenticated API request failed with status ' + str(status))
        return json.loads(content)
    if args.action == 'prepare':
        if not args.admin:
            raise ValueError('--admin is required for prepare')
        fields = dict(line.split(':', 1) for line in args.admin.read_text().splitlines() if ':' in line)
        status, headers, content = request('/api/login', {'username': fields['Username'].strip(), 'password': fields['Password'].strip()})
        if status != 200:
            raise RuntimeError('Public login failed with status ' + str(status))
        token = headers['Set-Cookie'].split(';', 1)[0].split('=', 1)[1]
        previous = {'cookie': token, 'csrf': json.loads(content)['csrf']}
    else:
        previous = json.loads(args.snapshot.read_text())
        token = previous['cookie']
        assert get_json('/api/session')['csrf'] == previous['csrf'], 'Original session no longer works'
    overview = get_json('/api/overview')
    if not args.allow_offline:
        assert overview['health']['core'], 'Controller has not become healthy'
    current = {'users': {}, 'static': {}}
    for user in overview['users']:
        links = get_json('/api/users/' + user['id'] + '/links')
        sub_path = urllib.parse.urlsplit(links['subscription']).path
        status, _, content = request(sub_path)
        current['users'][user['id']] = {'identity': {key: value for key, value in user.items() if key not in ('upload', 'download')},
            'links': links, 'subscription_status': status, 'subscription_sha256': hashlib.sha256(content).hexdigest(),
            'traffic': [user['upload'], user['download']]}
    for path in ('/', '/static/app.js', '/static/style.css'):
        status, _, content = request(path)
        assert status == 200, 'Static resource unavailable'
        current['static'][path] = hashlib.sha256(content).hexdigest()
    if args.action == 'prepare':
        previous.update(current)
        fd = os.open(args.snapshot, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(previous, stream)
        print(json.dumps({'public_snapshot_saved': True, 'users': len(current['users']), 'core_healthy': True}))
    else:
        if not args.allow_frontend_change:
            assert current['static'] == previous['static'], 'Frontend changed'
        assert current['users'].keys() == previous['users'].keys(), 'User list changed'
        for uid, user in current['users'].items():
            for key in ('identity', 'links', 'subscription_status', 'subscription_sha256'):
                assert user[key] == previous['users'][uid][key], key + ' changed'
            assert all(a >= b for a, b in zip(user['traffic'], previous['users'][uid]['traffic'])), 'Usage counters went backwards'
        print(json.dumps({'old_session_valid': True, 'users': len(current['users']), 'identities_preserved': True,
            'node_uris_identical': True, 'subscription_addresses_identical': True, 'subscription_contents_identical': True,
            'frontend_identical': current['static'] == previous['static'], 'traffic_monotonic': True, 'core_healthy': overview['health']['core']}))


if __name__ == '__main__':
    main()
