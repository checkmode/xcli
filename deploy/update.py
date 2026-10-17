#!/usr/bin/env python3
"""One-click frontend; all application mutations go through release.Manager."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True
import release
from build_environment import ensure_build_user


def update(source, revision, bundle=None, sha256=None):
    release.require(os.geteuid() == 0, '请使用 sudo 执行')
    release.require(re.fullmatch('[0-9a-f]{40}', revision), '需要完整的源码提交')
    release.require(bool(bundle) == bool(sha256), '--bundle 和 --sha256 必须一起使用')
    manager = release.Manager()
    with manager.lock():
        manager.guard()
    folder = Path('/var/backups/xcli/updates') / (release.stamp() + '-' + uuid.uuid4().hex[:8])
    folder.mkdir(parents=True, mode=0o700)
    log_path = folder / 'update.log'
    print('构建与更新日志：' + str(log_path), flush=True)
    work = None
    try:
        with log_path.open('x') as log:
            os.chmod(log_path, 0o600)
            def run(command):
                subprocess.run(list(map(str, command)), check=True, stdout=log, stderr=subprocess.STDOUT,
                    env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l',
                         'PYTHONDONTWRITEBYTECODE': '1'}, timeout=1800)
            if bundle is None:
                packages = (source / 'deploy/build-packages.txt').read_text().split()
                missing = [p for p in packages if subprocess.run(['dpkg-query', '-W', '-f=${Status}', p],
                    capture_output=True, text=True).stdout.strip() != 'install ok installed']
                if missing:
                    run(['apt-get', 'update'])
                    run(['apt-get', 'install', '-y', '--no-install-recommends', '--no-upgrade', *missing])
                builder = ensure_build_user(run)
                cache = Path('/var/cache/xcli/builds')
                cache.mkdir(parents=True, exist_ok=True)
                cache.chmod(0o755)
                cache.parent.chmod(0o755)
                work = Path(tempfile.mkdtemp(prefix='update-', dir=cache))
                shutil.chown(work, builder, builder)
                work.chmod(0o700)
                bundle = work / 'release.tar.gz'
                run(['runuser', '-u', builder, '-g', builder, '--', 'bash', source / 'deploy/build-source-release.sh',
                     source, revision, bundle])
                sha256 = release.digest(bundle)
            with manager.lock():
                manager.guard()
                staged = manager.stage(bundle, sha256)
                candidate, _ = manager.target(staged['staged'])
                manager.host.preflight(candidate)
            run(['bash', source / 'deploy/install-release-tools.sh'])
        if not manager.current.is_symlink():
            print('封存当前运行文件并建立版本基线。', flush=True)
            manager.adopt('baseline-' + release.stamp().lower() + '-' + uuid.uuid4().hex[:8])
        result = manager.activate(staged['staged'])
        release.atomic_json(folder / 'result.json', result)
        return result
    finally:
        if work is not None:
            shutil.rmtree(work)


def main(argv=None):
    p = argparse.ArgumentParser(description='构建或接收完整版本包，并通过 xcli-release 更新已有 1.3.0 部署')
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--commit', required=True)
    p.add_argument('--bundle', type=Path)
    p.add_argument('--sha256')
    a = p.parse_args(argv)
    os.umask(0o077)
    print(json.dumps(update(a.source.resolve(), a.commit, a.bundle, a.sha256), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (release.ReleaseError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('更新停止：' + str(error), file=sys.stderr)
        sys.exit(1)
