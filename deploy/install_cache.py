"""Root-only installer answers; never stores credential or private-key contents."""
import json
import os
from pathlib import Path
import stat
import tempfile

CACHE_PATH = Path('/root/.cache/xcli-install/answers.json')
MAX_BYTES = 16384
STRINGS = {'domain', 'public_ip', 'panel', 'email', 'reality_sni', 'dns_relay_ip',
           'certificate', 'private_key', 'bundle', 'sha256'}
BOOLEANS = {'no_email', 'coexist', 'tune_network'}
FIELDS = STRINGS | BOOLEANS | {'public_port'}


def _directory(path, create=False):
    directory = path.parent
    if create:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('安装输入缓存目录的权限或所有者不安全')
    return True


def _profile(value):
    if not isinstance(value, dict) or any(key not in FIELDS for key in value):
        raise ValueError('安装输入缓存格式不正确')
    for key, item in value.items():
        if key in STRINGS:
            if not isinstance(item, str) or len(item) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in item):
                raise ValueError('安装输入缓存格式不正确')
        elif key in BOOLEANS:
            if type(item) is not bool:
                raise ValueError('安装输入缓存格式不正确')
        elif type(item) is not int or not 1 <= item <= 65535:
            raise ValueError('安装输入缓存格式不正确')
    return value


def load(path=None):
    path = Path(path) if path is not None else CACHE_PATH
    if not _directory(path):
        return {'version': 1}
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {'version': 1}
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > MAX_BYTES:
            raise ValueError('安装输入缓存文件的权限或所有者不安全')
        with os.fdopen(fd, 'rb') as stream:
            fd = -1
            value = json.loads(stream.read(MAX_BYTES + 1))
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(value, dict) or value.get('version') != 1 or any(k not in {'version', 'last_role', 'panel', 'node'} for k in value):
        raise ValueError('安装输入缓存格式不正确')
    if value.get('last_role') not in (None, 'panel', 'node'):
        raise ValueError('安装输入缓存格式不正确')
    for role in ('panel', 'node'):
        if role in value:
            _profile(value[role])
    return value


def save(role, profile, path=None):
    if role not in ('panel', 'node'):
        raise ValueError('安装模式无效')
    path = Path(path) if path is not None else CACHE_PATH
    _directory(path, create=True)
    value = load(path)
    value[role] = _profile(profile)
    value['last_role'] = role
    encoded = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
    if len(encoded) > MAX_BYTES:
        raise ValueError('安装输入缓存超出允许大小')
    fd, temporary = tempfile.mkstemp(prefix='.answers-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
