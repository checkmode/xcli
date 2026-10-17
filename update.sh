#!/usr/bin/env bash
# Fetch one immutable revision; the release manager owns every switch and rollback.
set -euo pipefail
main() {
    local ref='' yes=0 check=0 rollback=0 bundle='' checksum='' work sha
    while (($#)); do
        case "$1" in
            --help|-h)
                cat <<'HELP'
xcli 一键更新（已有 1.3.0 部署）
固定源码提交，构建并校验完整版本包，再通过 xcli-release 切换。
未纳入版本管理的部署会先封存当前程序，之后使用同一发布与回退流程。
面板短暂重启；导入、监测、动态池仅在对应程序变化时重启。
保留用户、订阅、二次验证、累计流量、节点配置、Xray 和 Nginx。
  --yes            确认应用更新或回退
  --check          检查当前部署，不下载、不安装、不切换
  --ref COMMIT     指定完整的 40 位提交，默认解析 main
  --bundle FILE    使用已构建的版本包，跳过本机构建（须同时传入 --sha256）
  --sha256 SHA256  版本包的完整 SHA-256
  --rollback       通过 xcli-release 回退到前一个版本
  --help           显示帮助
全新服务器使用 install.sh；数据库或 Xray 跨版本升级需单独迁移。
HELP
                return 0 ;;
            --yes) yes=1; shift ;;
            --check) check=1; shift ;;
            --ref) [[ $# -ge 2 ]] || return 1; ref=$2; shift 2 ;;
            --bundle) [[ $# -ge 2 ]] || return 1; bundle=$2; shift 2 ;;
            --sha256) [[ $# -ge 2 ]] || return 1; checksum=$2; shift 2 ;;
            --rollback) rollback=1; shift ;;
            *) echo "未知选项：$1" >&2; return 1 ;;
        esac
    done
    [[ -z "$ref" || "$ref" =~ ^[0-9a-f]{40}$ ]] || { echo '--ref 必须是完整提交编号。' >&2; return 1; }
    [[ ( -z "$bundle" && -z "$checksum" ) || ( -f "$bundle" && "$checksum" =~ ^[0-9a-f]{64}$ ) ]] || { echo '--bundle 与有效 --sha256 必须一起使用。' >&2; return 1; }
    [[ $((check + rollback)) -le 1 ]] || { echo '--check 和 --rollback 不能同时使用。' >&2; return 1; }
    if ((check || rollback)); then
        [[ -z "$ref" && -z "$bundle" ]] || { echo '检查或回退不能同时指定新版本。' >&2; return 1; }
    fi
    [[ $EUID == 0 ]] || { echo '请通过 sudo bash 运行。' >&2; return 1; }
    [[ -d /run/systemd/system && -f /etc/os-release ]] || return 1
    . /etc/os-release
    [[ "$ID" == ubuntu && ( "$VERSION_ID" == 24.04 || "$VERSION_ID" == 26.04 ) ]] || return 1
    case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) return 1 ;; esac
    [[ -L /usr/local/lib/xray-gateway/panel-current && -f /etc/xray-gateway/security.key && -f /etc/xcli-monitor/monitor.json ]] || { echo '未找到完整的已有部署。' >&2; return 1; }
    [[ $(/usr/local/lib/xray-gateway/panel-current --version) == 'xray-gateway-panel 1.3.0 (C++20)' ]] || { echo '仅支持已有 1.3.0 面板，请先完成版本迁移。' >&2; return 1; }
    for service in xray-gateway-panel xray-gateway-core xray-gateway-monitor nginx; do systemctl is-active --quiet "$service"; done
    if [[ $check == 1 ]]; then
        if [[ -L /opt/xcli/current ]]; then exec /usr/local/sbin/xcli-release check; fi
        echo '旧 1.3.0 部署检查通过；更新时会先建立版本基线。未修改系统。'
        return 0
    fi
    if [[ $rollback == 1 && ! -L /opt/xcli/current ]]; then
        echo '尚未纳入版本管理，没有可供回退的完整版本。' >&2; return 1
    fi
    if [[ $yes == 0 ]]; then
        local answer
        printf '将切换应用版本；面板及代码变化的配套服务会短暂重启，是否继续？[y/N] ' >/dev/tty
        read -r answer </dev/tty
        [[ "$answer" == y || "$answer" == Y ]] || return 1
    fi
    if [[ $rollback == 1 ]]; then exec /usr/local/sbin/xcli-release rollback; fi
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
if not (work/'source/deploy/build-source-release.sh').is_file():
    raise SystemExit('该提交不支持统一版本发布；请选用包含 release.py 的新版本')
PY
    local -a update_args=(--source "$work/source" --commit "$sha")
    if [[ -n "$bundle" ]]; then update_args+=(--bundle "$(realpath -- "$bundle")" --sha256 "$checksum"); fi
    python3 -B "$work/source/deploy/update.py" "${update_args[@]}"
    rm -rf -- "$work"
    trap - EXIT
}
main "$@"
