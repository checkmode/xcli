#!/usr/bin/env bash
# Download one immutable source revision, then run its fresh-install wizard.
# Keep execution inside main so a truncated download cannot start installation.
set -euo pipefail

main() {
    local ref='' check_only=0 work sha
    local -a args=()
    while (($#)); do
        case "$1" in
            --help|-h)
                cat <<'HELP'
xcli 一键安装（无需 git clone）

支持 Ubuntu 24.04 / 26.04，AMD64 / ARM64，使用 systemd 的全新服务器。
直接运行后按提示填写域名、证书邮箱和公网 IPv4。

选项：
  --domain DOMAIN       面板域名，A 记录应只指向本机公网 IPv4
  --email EMAIL         Let's Encrypt 账户邮箱
  --public-ip IPV4      公网 IPv4；省略时自动检测并供确认
  --reality-sni DOMAIN  REALITY 目标，默认 www.bing.com
  --agree-tos           同意 Let's Encrypt 服务条款
  --yes                 确认安装；无人值守时还需提供全部必填参数
  --certificate FILE    使用已有受信任的证书链（与 --private-key 配对）
  --private-key FILE    已有证书的私钥；文件须可供 root 读取
  --check               只检查环境、端口和 DNS，不安装软件或改配置
  --ref COMMIT          安装指定的 40 位 Git 提交，默认解析 main
  --help                显示帮助

安装器遇到已有 xcli 或 Nginx 配置会退出，不覆盖现有站点。
HELP
                return 0 ;;
            --ref) [[ $# -ge 2 ]] || { echo '--ref 缺少提交编号' >&2; return 1; }; ref=$2; shift 2 ;;
            --source|--commit) echo '该选项仅供仓库内安装器使用' >&2; return 1 ;;
            --check) check_only=1; args+=("$1"); shift ;;
            *) args+=("$1"); shift ;;
        esac
    done
    [[ $EUID == 0 ]] || { echo '请使用 root 或通过 sudo bash 运行安装器。' >&2; return 1; }
    [[ $(uname -s) == Linux && -f /etc/os-release && -d /run/systemd/system ]] || { echo '需要使用 systemd 的 Ubuntu 服务器。' >&2; return 1; }
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "$ID" == ubuntu && ( "$VERSION_ID" == 24.04 || "$VERSION_ID" == 26.04 ) ]] || { echo '当前支持 Ubuntu 24.04 / 26.04。' >&2; return 1; }
    case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) echo '当前支持 AMD64 / ARM64。' >&2; return 1 ;; esac
    for work in /etc/xray-gateway /var/lib/xray-gateway /usr/local/lib/xray-gateway /opt/xray-gateway /etc/nginx/nginx.conf; do
        [[ ! -e "$work" && ! -L "$work" ]] || { echo "检测到已有配置：$work；安装已停止，请使用 README 中的升级流程。" >&2; return 1; }
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
    else
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 60 \
            https://api.github.com/repos/checkmode/xcli/commits/main -o "$work/revision.json"
        sha=$(python3 -c 'import json,re,sys; s=json.load(open(sys.argv[1]))["sha"]; assert re.fullmatch("[0-9a-f]{40}",s); print(s)' "$work/revision.json")
    fi
    printf '正在下载 xcli 源码版本 %s（自动构建，无需下载或克隆仓库）\n' "${sha:0:12}"
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 180 \
        "https://codeload.github.com/checkmode/xcli/tar.gz/$sha" -o "$work/source.tar.gz"
    python3 - "$work" "$sha" <<'PY'
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
PY
    python3 "$work/source/deploy/install.py" --source "$work/source" --commit "$sha" "${args[@]}"
    rm -rf -- "$work"
    trap - EXIT
}

main "$@"
