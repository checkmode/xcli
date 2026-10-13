"""Private state snapshots for migration, without printing credentials or hashes."""
import argparse
import hashlib
import json
import os
import pathlib
import sqlite3


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()).hexdigest()


def snapshot(database, settings):
    with sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute('BEGIN')
        users = [dict(row) for row in db.execute('SELECT * FROM users ORDER BY id')]
        identity = [{key: value for key, value in row.items() if key not in ('upload', 'download')} for row in users]
        sessions = {row['hash']: digest(dict(row)) for row in db.execute('SELECT * FROM sessions')}
        return {'identity_digest': digest(identity), 'admin_digest': digest([dict(row) for row in db.execute('SELECT * FROM admin')]),
            'sessions': sessions, 'settings_digest': hashlib.sha256(settings.read_bytes()).hexdigest(),
            'traffic': {row['id']: [row['upload'], row['download']] for row in users},
            'users': len(users), 'integrity': db.execute('PRAGMA quick_check').fetchone()[0]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['save', 'verify'])
    parser.add_argument('snapshot', type=pathlib.Path)
    parser.add_argument('--database', type=pathlib.Path, default=pathlib.Path('/var/lib/xray-gateway/gateway.sqlite'))
    parser.add_argument('--settings', type=pathlib.Path, default=pathlib.Path('/etc/xray-gateway/settings.json'))
    args = parser.parse_args()
    current = snapshot(args.database, args.settings)
    assert current['integrity'] == 'ok', 'Database integrity failed'
    if args.action == 'save':
        fd = os.open(args.snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(current, stream)
        print(json.dumps({'snapshot_saved': True, 'users': current['users']}))
        return
    previous = json.loads(args.snapshot.read_text())
    for key in ('identity_digest', 'admin_digest', 'settings_digest'):
        assert current[key] == previous[key], key + ' changed'
    assert all(current['sessions'].get(key) == value for key, value in previous['sessions'].items()), 'Existing sessions changed'
    for uid, traffic in previous['traffic'].items():
        assert all(a >= b for a, b in zip(current['traffic'][uid], traffic)), 'Traffic counters went backwards'
    print(json.dumps({'identity_preserved': True, 'password_preserved': True, 'settings_preserved': True,
        'existing_sessions_preserved': True, 'traffic_monotonic': True, 'users': current['users'], 'integrity': 'ok'}))


if __name__ == '__main__':
    main()
