#!/usr/bin/env bash
# Download one immutable source revision, then run its fresh-install wizard.
# Keep execution inside main so a truncated download cannot start installation.
set -euo pipefail

cache_field() {
    command -v python3 >/dev/null || return 0
    python3 - "$1" "${2:-}" 2>/dev/null <<'PY' || true
import json, os, stat, sys
path='/root/.cache/xcli-install/answers.json'
try:
    directory=os.lstat(os.path.dirname(path))
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=os.geteuid() or directory.st_mode & 0o077:
        raise ValueError
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o077 or info.st_size>16384:
            raise ValueError
        data=json.load(stream)
    if data.get('version')!=1: raise ValueError
    if sys.argv[1]=='role' and data.get('last_role') in ('panel','node'):
        print(data['last_role'])
    elif sys.argv[1]=='coexist' and sys.argv[2] in ('panel','node'):
        print('true' if data.get(sys.argv[2],{}).get('coexist') is True else 'false')
except (OSError, ValueError, TypeError, AttributeError):
    pass
PY
}

main() {
    local ref='' role='' noninteractive=0 check_only=0 coexist=0 coexist_explicit=0 no_cache=0 legacy=0 work sha repo_root script_dir default_role
    local script_origin="${BASH_SOURCE[0]:-}"
    local -a args=()
    while (($#)); do
        case "$1" in
            --help|-h)
                cat <<'HELP'
xcli 一键安装（无需 git clone；默认安装 Rust / Node.js / Vue 测试版）

支持 Ubuntu 24.04 / 26.04，AMD64 / ARM64，使用 systemd 的全新服务器。
直接运行后选择面板或独立节点，并按提示填写域名、证书邮箱和公网 IPv4。

选项：
  --role panel|node     安装面板（同时提供节点）或独立节点
  --panel HTTPS_URL     独立节点连接的已有面板 HTTPS 地址
  --domain DOMAIN       面板或节点域名，A 记录应只指向本机公网 IPv4
  --email EMAIL         Let's Encrypt 账户邮箱
  --no-email            不提供证书到期通知邮箱（仍启用自动续期）
  --public-ip IPV4      公网 IPv4；省略时自动检测并供确认
  --dns-relay-ip IPV4   旧版：域名通过另一台主机转发时的公网 IPv4
  --reality-sni DOMAIN  REALITY 目标，默认 www.bing.com
  --agree-tos           同意 Let's Encrypt 服务条款
  --yes                 确认安装；无人值守时还需提供全部必填参数
  --certificate FILE    使用已有受信任的证书链（与 --private-key 配对）
  --private-key FILE    已有证书的私钥；文件须可供 root 读取
  --tune-network        旧版：可选 BBR / fq 与 UDP 缓冲调优
  --no-tune-network     保留现有网络参数（无人值守时默认）
  --coexist             旧版：在已有服务的主机使用独立 Nginx 配置
  --no-coexist          不使用缓存中的共存设置
  --no-cache            忽略输入缓存，检查时也不写入
  --public-port PORT    独立的 TCP / UDP 入口端口（默认 443）
  --bundle FILE         旧版：使用匹配系统及提交的预构建版本包
  --sha256 SHA256       旧版预构建版本包的 SHA-256
  --check               检查环境、端口和 DNS，并缓存安装输入，不安装软件或改服务配置
  --ref COMMIT          安装指定的 40 位 Git 提交；克隆仓库默认当前提交，否则使用 main
  --legacy              安装旧版 C++ 面板或旧版节点
  --help                显示帮助

安装器遇到已有 xcli 配置会退出；新版仅支持全新安装。
HELP
                return 0 ;;
            --ref) [[ $# -ge 2 ]] || { echo '--ref 缺少提交编号' >&2; return 1; }; ref=$2; shift 2 ;;
            --role) [[ $# -ge 2 ]] || { echo '--role 缺少值' >&2; return 1; }; role=$2; shift 2 ;;
            --role=*) role=${1#--role=}; shift ;;
            --source|--commit) echo '该选项仅供仓库内安装器使用' >&2; return 1 ;;
            --yes) noninteractive=1; args+=("$1"); shift ;;
            --check) check_only=1; args+=("$1"); shift ;;
            --coexist) coexist=1; coexist_explicit=1; args+=("$1"); shift ;;
            --no-coexist) coexist=0; coexist_explicit=1; args+=("$1"); shift ;;
            --no-cache) no_cache=1; args+=("$1"); shift ;;
            --legacy) legacy=1; shift ;;
            *) args+=("$1"); shift ;;
        esac
    done
    if [[ -z "$role" && $noninteractive == 0 ]]; then
        default_role=1
        if ((no_cache == 0)) && [[ $(cache_field role) == node ]]; then default_role=2; fi
        if [[ -r /dev/tty && -w /dev/tty ]] && { exec 3<>/dev/tty; } 2>/dev/null; then
            printf '安装模式：\n  1) 面板及本机节点\n  2) 独立服务器节点\n请选择 [%s]: ' "$default_role" >&3
            IFS= read -r role <&3 || { echo '输入已结束，安装取消' >&2; return 1; }
            role=${role:-$default_role}
            exec 3>&-
        else
            echo '无法访问交互终端；请指定 --role panel 或 --role node 及必需参数。' >&2
            return 1
        fi
    fi
    case "$role" in ''|1|panel) role=panel ;; 2|node) role=node ;; *) echo '安装模式必须为 panel 或 node。' >&2; return 1 ;; esac
    if ((noninteractive == 0 && no_cache == 0 && coexist_explicit == 0)) && [[ $(cache_field coexist "$role") == true ]]; then
        coexist=1
    fi
    [[ $EUID == 0 ]] || { echo '请使用 root 或通过 sudo bash 运行安装器。' >&2; return 1; }
    [[ $(uname -s) == Linux && -f /etc/os-release && -d /run/systemd/system ]] || { echo '需要使用 systemd 的 Ubuntu 服务器。' >&2; return 1; }
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "$ID" == ubuntu && ( "$VERSION_ID" == 24.04 || "$VERSION_ID" == 26.04 ) ]] || { echo '当前支持 Ubuntu 24.04 / 26.04。' >&2; return 1; }
    case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) echo '当前支持 AMD64 / ARM64。' >&2; return 1 ;; esac
    for work in /etc/xray-gateway /var/lib/xray-gateway /usr/local/lib/xray-gateway /opt/xray-gateway /opt/xcli /usr/local/lib/xcli /var/lib/xcli /var/backups/xcli /var/cache/xcli /etc/xcli-node /var/lib/xcli-node /usr/local/lib/xcli-node /etc/nginx/nginx.conf; do
        [[ $coexist == 0 || "$work" != /etc/nginx/nginx.conf ]] || continue
        [[ ! -e "$work" && ! -L "$work" ]] || { echo "检测到已有配置：$work；安装已停止，请查阅 README 中的维护说明。" >&2; return 1; }
    done
    if ! command -v python3 >/dev/null; then
        [[ $check_only == 0 ]] || { echo '只检查模式需要系统已安装 python3。' >&2; return 1; }
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 ca-certificates
    fi
    command -v curl >/dev/null || { echo '请先安装 curl。' >&2; return 1; }
    [[ -z "$ref" || "$ref" =~ ^[0-9a-f]{40}$ ]] || { echo '--ref 必须是完整的 40 位提交编号。' >&2; return 1; }
    work=$(mktemp -d /var/tmp/xcli-installer.XXXXXXXX)
    # mktemp returns a controlled path; expand it now, before main's local scope ends.
    trap "rm -rf -- '$work'" EXIT
    chmod 755 "$work"
    if [[ -n "$ref" ]]; then
        sha=$ref
    elif [[ -n "$script_origin" && -f "$script_origin" && -e "$(dirname -- "$script_origin")/.git" ]]; then
        command -v git >/dev/null || { echo '检测到 Git 检出，但无法运行 git 读取当前提交。' >&2; return 1; }
        script_dir=$(cd -- "$(dirname -- "$script_origin")" && pwd -P)
        repo_root=$(git -c safe.directory="$script_dir" -C "$script_dir" rev-parse --show-toplevel 2>/dev/null) ||
            { echo '无法读取当前仓库，请检查 Git 仓库所有权和 safe.directory。' >&2; return 1; }
        sha=$(git -c safe.directory="$repo_root" -C "$repo_root" rev-parse HEAD)
        [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo '无法确定当前仓库提交。' >&2; return 1; }
        printf '使用当前检出提交 %s；本地未提交内容不会包含在安装包中。\n' "${sha:0:12}"
    else
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 60 \
            https://api.github.com/repos/checkmode/xcli/commits/main -o "$work/revision.json"
        sha=$(python3 -c 'import json,re,sys; s=json.load(open(sys.argv[1]))["sha"]; assert re.fullmatch("[0-9a-f]{40}",s); print(s)' "$work/revision.json")
    fi
    if ((check_only)); then
        if ((no_cache)); then
            printf '正在下载固定源码 %s，随后检查环境（不会缓存输入或修改服务配置）\n' "${sha:0:12}"
        else
            printf '正在下载固定源码 %s，随后检查环境并缓存安装输入（不会安装软件或修改服务配置）\n' "${sha:0:12}"
        fi
    elif [[ $role == node ]]; then
        printf '正在下载固定源码 %s，随后安装独立服务器节点\n' "${sha:0:12}"
    else
        printf '正在下载固定源码 %s，构建完整版本后安装到 /opt/xcli/releases/\n' "${sha:0:12}"
    fi
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 180 \
        "https://codeload.github.com/checkmode/xcli/tar.gz/$sha" -o "$work/source.tar.gz"
    python3 - "$work" "$sha" "$legacy" <<'PY'
import pathlib,sys,tarfile
work=pathlib.Path(sys.argv[1]);prefix='xcli-'+sys.argv[2]
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
required = 'deploy/build-source-release.sh' if sys.argv[3]=='1' else 'rewrite/install-experimental.sh'
if not (work/'source'/required).is_file():
    raise SystemExit('该提交不包含所选版本的安装器')
PY
    if ((legacy == 0)); then
        [[ -f "$work/source/rewrite/install-experimental.sh" ]] || {
            echo '该提交尚不包含 Rust 安装器，请使用包含重构代码的提交。' >&2; return 1;
        }
        XCLI_REWRITE_ARCHIVE_SOURCE="$work/source" XCLI_REWRITE_REVISION="$sha" \
            bash "$work/source/rewrite/install-experimental.sh" --role "$role" "${args[@]}"
    elif [[ $role == node ]]; then
        python3 "$work/source/deploy/install_node.py" --source "$work/source" --commit "$sha" "${args[@]}"
    else
        python3 "$work/source/deploy/install.py" --source "$work/source" --commit "$sha" "${args[@]}"
    fi
    rm -rf -- "$work"
    trap - EXIT
}

main "$@"
