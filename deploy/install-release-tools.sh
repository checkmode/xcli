#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo '请使用 sudo 执行。' >&2; exit 1; }
exec 9>/run/lock/xcli-update.lock
flock -n 9 || { echo '发布或节点操作正在运行，稍后重试安装工具。' >&2; exit 1; }
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
revision=$(cat "$source_dir/release.py" "$source_dir/migrate-layout.py" "$source_dir/xcli-admin.sh" | sha256sum | cut -c1-16)
target=/usr/local/lib/xcli/release-tools/$revision
if [[ -d "$target" ]]; then
    cmp "$source_dir/release.py" "$target/release.py"
    cmp "$source_dir/migrate-layout.py" "$target/migrate-layout.py"
    cmp "$source_dir/xcli-admin.sh" "$target/xcli-admin.sh"
else
    install -d -m755 "$target"
    install -m555 "$source_dir/release.py" "$target/release.py"
    install -m555 "$source_dir/migrate-layout.py" "$target/migrate-layout.py"
    install -m555 "$source_dir/xcli-admin.sh" "$target/xcli-admin.sh"
fi
ln -s "$target" /usr/local/lib/xcli/.tools-current.$$
mv -Tf /usr/local/lib/xcli/.tools-current.$$ /usr/local/lib/xcli/tools-current
ln -sfn /usr/local/lib/xcli/tools-current/release.py /usr/local/sbin/xcli-release
ln -sfn /usr/local/lib/xcli/tools-current/migrate-layout.py /usr/local/sbin/xcli-layout
ln -sfn /usr/local/lib/xcli/tools-current/xcli-admin.sh /usr/local/sbin/xcli-admin
printf '发布工具已安装：%s\n' "$target"
