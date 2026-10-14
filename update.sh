#!/usr/bin/env bash
# Fetch one immutable revision and update only an existing compatible panel.
set -euo pipefail
main() {
    local ref='' yes=0 check=0 work sha
    while (($#)); do
        case "$1" in
            --help|-h)
                cat <<'HELP'
xcli 一键更新（已有 1.3.0 部署）
自动下载固定提交、安装缺少的编译依赖、编译并测试，然后备份和更新管理面板。
只重启面板；保留用户、订阅、二次验证、累计流量和节点配置。
Xray、Nginx、探测服务与系统网络参数保持现状。
  --yes          确认更新，管理面板会短暂中断
  --check        只检查已有部署，不下载、不安装、不更新
  --ref COMMIT   指定完整的 40 位提交，默认解析 main
  --help         显示帮助
旧版部署请先按 README 完成版本迁移；全新服务器使用 install.sh。
HELP
                return 0 ;;
            --yes) yes=1; shift ;;
            --check) check=1; shift ;;
            --ref) [[ $# -ge 2 ]] || return 1; ref=$2; shift 2 ;;
            *) echo "未知选项：$1" >&2; return 1 ;;
        esac
    done
    [[ $EUID == 0 ]] || { echo '请通过 sudo bash 运行。' >&2; return 1; }
    [[ -d /run/systemd/system && -f /etc/os-release ]] || return 1
    . /etc/os-release
    [[ "$ID" == ubuntu && ( "$VERSION_ID" == 24.04 || "$VERSION_ID" == 26.04 ) ]] || return 1
    case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) return 1 ;; esac
    [[ -L /usr/local/lib/xray-gateway/panel-current && -f /etc/xray-gateway/security.key && -f /etc/xcli-monitor/monitor.json ]] || { echo '未找到完整的已有部署。' >&2; return 1; }
    [[ $(/usr/local/lib/xray-gateway/panel-current --version) == 'xray-gateway-panel 1.3.0 (C++20)' ]] || { echo '仅支持已有 1.3.0 面板，请先完成版本迁移。' >&2; return 1; }
    for service in xray-gateway-panel xray-gateway-core xray-gateway-monitor nginx; do systemctl is-active --quiet "$service"; done
    [[ -z "$ref" || "$ref" =~ ^[0-9a-f]{40}$ ]] || { echo '--ref 必须是完整提交编号。' >&2; return 1; }
    [[ $check == 0 ]] || { echo '已有 1.3.0 部署与四个服务检查通过；未修改系统。'; return 0; }
    if [[ $yes == 0 ]]; then
        local answer
        printf '更新会短暂重启管理面板，是否继续？[y/N] ' >/dev/tty
        read -r answer </dev/tty
        [[ "$answer" == y || "$answer" == Y ]] || return 1
    fi
    exec 9>/run/lock/xcli-update.lock
    flock -n 9 || { echo '另一项面板更新正在运行。' >&2; return 1; }
    work=$(mktemp -d /var/tmp/xcli-updater.XXXXXXXX)
    chmod 755 "$work"
    trap "rm -rf -- '$work'" EXIT
    if [[ -n "$ref" ]]; then sha=$ref; else
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 60 \
            https://api.github.com/repos/checkmode/xcli/commits/main -o "$work/revision.json"
        sha=$(python3 -c 'import json,re,sys; s=json.load(open(sys.argv[1]))["sha"]; assert re.fullmatch("[0-9a-f]{40}",s); print(s)' "$work/revision.json")
    fi
    printf '正在下载固定提交 %s\n' "$sha"
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 180 \
        "https://codeload.github.com/checkmode/xcli/tar.gz/$sha" -o "$work/source.tar.gz"
    python3 - "$work" "$sha" <<'PY'
import pathlib,sys,tarfile
work=pathlib.Path(sys.argv[1]); prefix='xcli-'+sys.argv[2]
with tarfile.open(work/'source.tar.gz','r:gz') as archive:
    members=archive.getmembers()
    if len(members)>10000 or sum(m.size for m in members)>100*1024*1024:
        raise SystemExit('源码包超出预期大小')
    for member in members:
        path=pathlib.PurePosixPath(member.name)
        if not path.parts or path.parts[0]!=prefix or path.is_absolute() or '..' in path.parts or not (member.isdir() or member.isfile()):
            raise SystemExit('源码包包含不安全路径或链接')
    archive.extractall(work,filter='data')
(work/prefix).rename(work/'source')
PY
    bash "$work/source/deploy/update-panel.sh" "$work/source" "$sha"
    rm -rf -- "$work"
    trap - EXIT
}
main "$@"
