"""Durable, replay-safe per-user accounting for a remote Xray node."""
import re
import sqlite3
from pathlib import Path

MAX_COUNTER = (1 << 63) - 1
_COUNTER = re.compile(r'user>>>([0-9a-f]{32})\.[0-9a-f]{8}@(reality|websocket|hysteria2)>>>traffic>>>(uplink|downlink)\Z')
_USER = re.compile(r'[0-9a-f]{32}\Z')


class LedgerError(RuntimeError):
    pass


class Ledger:
    """Persist cumulative totals independently of Xray process generations.

    A report remains pending until acknowledged. Sending it twice is harmless:
    panel-side accounting uses cumulative totals, not packet or request counts.
    """
    def __init__(self, path):
        self.path = Path(path)
        if self.path.is_symlink():
            raise LedgerError('Accounting database must not be a symlink')
        # NodeAgent serializes the watchdog and sync thread with its lock.
        self.db = sqlite3.connect(self.path, timeout=15, isolation_level=None, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS node_totals (
                user_id TEXT PRIMARY KEY, upload INTEGER NOT NULL DEFAULT 0,
                download INTEGER NOT NULL DEFAULT 0, ack_upload INTEGER NOT NULL DEFAULT 0,
                ack_download INTEGER NOT NULL DEFAULT 0, last_ack INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS node_counters (
                name TEXT PRIMARY KEY, generation TEXT NOT NULL, value INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS node_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
            INSERT OR IGNORE INTO node_meta VALUES ('ack_sequence', 0);
        ''')

    def close(self):
        self.db.close()

    def record(self, generation, counters):
        if not isinstance(generation, str) or not generation or len(generation) > 128:
            raise LedgerError('Invalid core generation')
        if not isinstance(counters, list) or len(counters) > 10000:
            raise LedgerError('Invalid core counters')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            seen = set()
            for entry in counters:
                # Protobuf JSON omits the default value for an untouched counter.
                if not isinstance(entry, dict) or set(entry) not in ({'name'}, {'name', 'value'}):
                    raise LedgerError('Invalid counter')
                name = entry['name']
                if not isinstance(name, str) or len(name) > 200:
                    raise LedgerError('Invalid counter name')
                match = _COUNTER.fullmatch(name)
                if not match:
                    continue
                if name in seen:
                    raise LedgerError('Duplicate counter')
                seen.add(name)
                value = entry.get('value', 0)
                if isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,18}', value):
                    value = int(value)
                if type(value) is not int or not 0 <= value <= MAX_COUNTER:
                    raise LedgerError('Invalid counter value')
                previous = self.db.execute('SELECT generation,value FROM node_counters WHERE name=?', (name,)).fetchone()
                if previous and previous[0] == generation:
                    if value < previous[1]:
                        raise LedgerError('Core counter decreased within one generation')
                    delta = value - previous[1]
                else:
                    delta = value
                self.db.execute('INSERT OR IGNORE INTO node_totals(user_id) VALUES (?)', (match[1],))
                column = 'upload' if match[3] == 'uplink' else 'download'
                old = self.db.execute('SELECT '+column+' FROM node_totals WHERE user_id=?', (match[1],)).fetchone()[0]
                if delta > MAX_COUNTER - old:
                    raise LedgerError('Traffic total overflow')
                self.db.execute('UPDATE node_totals SET '+column+'=? WHERE user_id=?', (old + delta, match[1]))
                self.db.execute('INSERT INTO node_counters VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET generation=excluded.generation,value=excluded.value', (name, generation, value))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def pending(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 500:
            raise LedgerError('Invalid report limit')
        rows = self.db.execute('SELECT user_id,upload,download FROM node_totals WHERE upload!=ack_upload OR download!=ack_download ORDER BY last_ack,user_id LIMIT ?', (limit,)).fetchall()
        return [{'id': uid, 'upload': up, 'download': down} for uid, up, down in rows]

    def acknowledge(self, entries):
        if not isinstance(entries, list) or len(entries) > 500:
            raise LedgerError('Invalid accounting acknowledgement')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            sequence = self.db.execute("SELECT value FROM node_meta WHERE key='ack_sequence'").fetchone()[0]
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {'id', 'upload', 'download'}:
                    raise LedgerError('Invalid accounting acknowledgement')
                uid, up, down = entry['id'], entry['upload'], entry['download']
                if not isinstance(uid, str) or not _USER.fullmatch(uid) or type(up) is not int or type(down) is not int:
                    raise LedgerError('Invalid accounting acknowledgement')
                row = self.db.execute('SELECT upload,download,ack_upload,ack_download FROM node_totals WHERE user_id=?', (uid,)).fetchone()
                if not row or not 0 <= up <= row[0] or not 0 <= down <= row[1] or up < row[2] or down < row[3]:
                    raise LedgerError('Acknowledgement does not match local accounting')
                sequence += 1
                self.db.execute('UPDATE node_totals SET ack_upload=?,ack_download=?,last_ack=? WHERE user_id=?', (up, down, sequence, uid))
            self.db.execute("UPDATE node_meta SET value=? WHERE key='ack_sequence'", (sequence,))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
