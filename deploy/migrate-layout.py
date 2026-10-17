#!/usr/bin/env python3
"""Reversible archival of the Oracle legacy layout after release adoption."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('release', Path(__file__).resolve().with_name('release.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

HOME_EXTRAS = {'app.js', 'index.html', 'style.css', 'proxy_import.py', 'renewal.sh', 'live_smoke.py',
               'clash-export-check.py', 'clash-verify-live.py', 'deploy-shadowrocket-panel.sh'}
RUNTIME_FILES = ['certificate.py', 'network.py', 'firewall.sh', 'renewal.sh']


def candidates():
    result = []
    for root in (Path('/home/ubuntu'), Path('/root'), Path('/var/tmp')):
        if not root.is_dir():
            continue
        for p in sorted(root.iterdir()):
            name = p.name.lower()
            selected = name.startswith(('xcli-', 'xray-gateway-', 'xg-', 'webshare-check-', 'iproyal-'))
            if root == Path('/home/ubuntu'):
                selected |= p.name in HOME_EXTRAS or name == 'xray-macos-arm64-v8a.zip'
            if selected and not p.is_symlink():
                result.append(p)
    legacy = Path('/opt/xray-gateway')
    if not (legacy / 'LAYOUT.txt').is_file():
        result.append(legacy)
    result.append(Path('/usr/local/lib/xray-gateway/releases'))
    return [p for p in result if p.exists()]


def references(paths):
    # Prevent moving any live process's executable, cwd, argument or open file.
    hits = []
    def under(name): return any(name == str(p) or name.startswith(str(p) + '/') for p in paths)
    for process in Path('/proc').glob('[0-9]*'):
        try:
            refs = [os.readlink(process / 'cwd'), os.readlink(process / 'exe')]
            refs.extend(x.decode(errors='replace') for x in (process / 'cmdline').read_bytes().split(b'\0') if x.startswith(b'/'))
            for fd in (process / 'fd').iterdir():
                try: refs.append(os.readlink(fd))
                except OSError: pass
            for ref in refs:
                if under(ref): hits.append({'pid': int(process.name), 'path': ref})
        except (OSError, PermissionError): pass
    return hits


def plan(destination):
    r.require(not destination.exists(), '归档目录已经存在')
    r.require(Path('/opt/xcli/current').is_symlink(), '先建立并验证完整版本基线')
    paths = candidates()
    # Running Python workers keep their old cwd/argv; identical code is retained through compatibility links.
    hits = references([p for p in paths if p != Path('/opt/xray-gateway')])
    r.require(not hits, '遗留目录仍被进程引用；先查看计划并停止对应测试进程')
    destination.mkdir(parents=True, mode=0o700)
    rows = []
    for path in paths:
        s = path.lstat()
        rows.append({'source': str(path), 'destination': str(destination / 'files' / path.relative_to('/')),
                     'device': s.st_dev, 'inode': s.st_ino, 'mode': s.st_mode & 0o7777,
                     'uid': s.st_uid, 'gid': s.st_gid, 'moved': False})
    value = {'format': 1, 'created_at': r.stamp(), 'status': 'planned', 'entries': rows,
             'compatibility': '/opt/xray-gateway', 'support': '/usr/local/lib/xcli/host'}
    r.atomic_json(destination / 'manifest.json', value)
    print(json.dumps({'plan': str(destination / 'manifest.json'), 'entries': len(rows),
                      'by_parent': {str(p): sum(Path(x['source']).parent == p for x in rows)
                                    for p in sorted({Path(x['source']).parent for x in rows})}}, indent=2))


def write_compatibility(path):
    r.write_compatibility(path)


def apply(manifest):
    value = json.loads(manifest.read_text())
    r.require(value['status'] == 'planned', '计划不是待执行状态')
    r.require(not Path('/var/lib/xcli/transaction.json').exists(), '存在未完成发布')
    paths = [Path(row['source']) for row in value['entries']]
    r.require(not references([p for p in paths if p != Path('/opt/xray-gateway')]), '归档对象又被进程引用')
    for row in value['entries']:
        path = Path(row['source']); s = path.lstat()
        r.require(s.st_dev == row['device'] and s.st_ino == row['inode'] and not path.is_symlink(), '计划后源路径发生变化')
        r.require(not Path(row['destination']).exists(), '归档目标已存在')
    compat = Path('/opt/.xcli-compatibility-new')
    if Path('/opt/xray-gateway') in paths:
        support = Path(value['support'])
        r.require(not support.exists(), '主机脚本目录已存在；先检查之前的迁移')
        support.mkdir(parents=True, mode=0o755)
        support.chmod(0o755)
        for name in RUNTIME_FILES:
            source = Path('/opt/xray-gateway/deploy') / name
            if source.exists():
                shutil.copy2(source, support / name)
                r.require(r.digest(source) == r.digest(support / name), '主机脚本复制校验失败')
        r.atomic_json(support / 'manifest.json', {p.name: r.digest(p) for p in support.iterdir()}, 0o444)
        r.require(not compat.exists(), '兼容目录临时路径已占用')
        write_compatibility(compat)
    value['status'] = 'moving'; r.atomic_json(manifest, value)
    try:
        for row in value['entries']:
            source, target = Path(row['source']), Path(row['destination'])
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # rename preserves contents, permissions, inode and ownership on this host's single filesystem.
            os.rename(source, target)
            row['moved'] = True; r.atomic_json(manifest, value)
            if source == Path('/opt/xray-gateway'):
                os.rename(compat, source)
        value['status'] = 'archived'; r.atomic_json(manifest, value)
    except BaseException:
        value['status'] = 'interrupted'; r.atomic_json(manifest, value)
        raise
    print(json.dumps({'status': value['status'], 'archived_entries': len(value['entries']), 'manifest': str(manifest)}))


def restore(manifest):
    value = json.loads(manifest.read_text())
    for row in reversed(value['entries']):
        source, target = Path(row['source']), Path(row['destination'])
        # An interruption between rename and journaling is detected from both paths.
        if not target.exists(): continue
        if source == Path('/opt/xray-gateway') and source.exists():
            r.require((source / 'LAYOUT.txt').is_file(), '兼容目录已改变，停止恢复')
            parked = manifest.parent / 'compatibility-after-migration'
            r.require(not parked.exists(), '兼容目录保留位置已存在')
            source.rename(parked)
        r.require(not source.exists() and not source.is_symlink(), '原位置已有文件，拒绝覆盖：' + str(source))
        os.rename(target, source)
        row['moved'] = False; r.atomic_json(manifest, value)
    value['status'] = 'restored'; r.atomic_json(manifest, value)
    print(json.dumps({'status': 'restored', 'note': 'Only file placement restored; services and business data were not rolled back.'}))


def main():
    p = argparse.ArgumentParser(description='归档 Oracle 遗留部署文件，并保留逐项位置恢复清单')
    sub = p.add_subparsers(dest='action', required=True)
    for action in ('plan', 'apply', 'restore'):
        child = sub.add_parser(action); child.add_argument('path', type=Path)
    args = p.parse_args()
    r.require(os.geteuid() == 0, '请使用 sudo 执行')
    os.umask(0o077)
    with r.Manager().lock():
        if args.action == 'plan': plan(args.path)
        elif args.action == 'apply': apply(args.path)
        else: restore(args.path)


if __name__ == '__main__':
    try: main()
    except (r.ReleaseError, OSError, ValueError) as error:
        print('目录迁移：' + str(error), file=sys.stderr); sys.exit(1)
