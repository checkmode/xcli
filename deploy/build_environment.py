"""Keep host builds separate from runtime identities and their network policy."""
import grp
import pwd


BUILD_USER = 'xcli-build'
BUILD_COMMENT = 'xcli release builder'


def ensure_build_user(run):
    try:
        account = pwd.getpwnam(BUILD_USER)
    except KeyError:
        try:
            grp.getgrnam(BUILD_USER)
        except KeyError:
            pass
        else:
            raise ValueError('构建组 xcli-build 已存在但没有对应账号，请先核对其用途')
        run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
             '--shell', '/usr/sbin/nologin', '--comment', BUILD_COMMENT, BUILD_USER])
        account = pwd.getpwnam(BUILD_USER)
    group = grp.getgrnam(BUILD_USER)
    if not (0 < account.pw_uid < 1000 and group.gr_gid > 0 and account.pw_gid == group.gr_gid
            and account.pw_dir == '/nonexistent' and account.pw_shell == '/usr/sbin/nologin'
            and account.pw_gecos == BUILD_COMMENT and not group.gr_mem
            and all(BUILD_USER not in other.gr_mem for other in grp.getgrall())
            and all(other.pw_name == BUILD_USER or other.pw_uid != account.pw_uid for other in pwd.getpwall())):
        raise ValueError('构建账号 xcli-build 的身份或权限不符合要求，请先核对；未修改已有账号')
    return BUILD_USER
