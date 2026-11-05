#!/usr/bin/env bash
# Fresh installation of the rewrite from the current committed checkout.
set -euo pipefail
main() {
  local root revision role='' answer='' check=0 noninteractive=0 work arch node_arch node_hash node_version=24.22.2 archive_source
  local -a args=()
  root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
  while (($#)); do
    case "$1" in
      --help|-h)
        cat <<'HELP'
实验性 Rust / Node / Vue 新安装器（尚未通过生产验收）

用法：sudo bash rewrite/install-experimental.sh [--role panel|node] [安装选项]
运行后可选择面板或独立节点，并填写域名、IP 和证书信息。只支持干净的 Ubuntu 24.04 / 26.04。
--check 仅检查环境与输入；--yes 用于无人值守，需提供 --role、--domain、--public-ip、证书选项等参数。
克隆仓库后使用当前 Git 提交；未提交内容不会用于安装。已有部署请勿使用此脚本升级。
HELP
        return 0 ;;
      --role) [[ $# -ge 2 ]] || { echo '--role 缺少值' >&2; return 1; }; role=$2; shift 2 ;;
      --role=*) role=${1#--role=}; shift ;;
      --check) check=1; args+=("$1"); shift ;;
      --yes) noninteractive=1; args+=("$1"); shift ;;
      --source|--commit|--release-dir|--node-bin|--experimental)
        echo "内部参数不可用于一键安装：$1" >&2; return 1 ;;
      *) args+=("$1"); shift ;;
    esac
  done
  if [[ -z "$role" && "$noninteractive" == 0 ]]; then
    if [[ -r /dev/tty && -w /dev/tty ]] && { exec 3<>/dev/tty; } 2>/dev/null; then
      printf '安装模式：\n  1) 面板及本机节点\n  2) 独立服务器节点\n请选择 [1]: ' >&3
      IFS= read -r answer <&3 || { echo '输入已结束，安装取消' >&2; return 1; }
      exec 3>&-
      role=${answer:-1}
    else
      echo '无法访问交互终端，请使用 --role panel 或 --role node。' >&2; return 1
    fi
  fi
  case "$role" in 1|panel) role=panel ;; 2|node) role=node ;; *) echo '请选择 panel 或 node。' >&2; return 1 ;; esac
  [[ $EUID == 0 ]] || { echo '请使用 root 或 sudo 运行。' >&2; return 1; }
  command -v python3 >/dev/null && command -v curl >/dev/null || {
    echo '请先安装 python3 和 curl。' >&2; return 1;
  }
  archive_source="${XCLI_REWRITE_ARCHIVE_SOURCE:-}"
  if [[ -n "$archive_source" ]]; then
    [[ -d "$archive_source/rewrite/deploy" && -f "$archive_source/rewrite/build-release.sh" ]] || {
      echo '安装源码不完整。' >&2; return 1;
    }
    revision="${XCLI_REWRITE_REVISION:-}"
  else
    command -v git >/dev/null || { echo '请先安装 git。' >&2; return 1; }
    revision="$(git -c safe.directory="$root" -C "$root" rev-parse HEAD)"
  fi
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo '无法读取当前 Git 提交。' >&2; return 1; }
  printf '安装版本：%s（未提交的更改不包含在内）\n' "${revision:0:12}"
  work="$(mktemp -d /var/tmp/xcli-rewrite-build.XXXXXXXX)"
  trap "rm -rf -- '$work'" EXIT
  chmod 0755 "$work"
  mkdir "$work/source"
  if [[ -n "$archive_source" ]]; then
    cp -R "$archive_source/." "$work/source/"
  else
    git -c safe.directory="$root" -C "$root" archive "$revision" | tar -x -C "$work/source"
  fi
  [[ -f "$work/source/rewrite/deploy/install-experimental.py" ]] || {
    echo '当前提交不包含重构安装器，请先提交代码。' >&2; return 1;
  }
  if ((check)); then
    python3 "$work/source/rewrite/deploy/install-experimental.py" --experimental --role "$role" \
      --source "$work/source" --commit "$revision" "${args[@]}"
    return
  fi
  [[ $(uname -s) == Linux && -d /run/systemd/system && -f /etc/os-release ]] || {
    echo '需要运行 systemd 的 Ubuntu 服务器。' >&2; return 1;
  }
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "$ID" == ubuntu && ( "$VERSION_ID" == 24.04 || "$VERSION_ID" == 26.04 ) ]] || {
    echo '当前支持 Ubuntu 24.04 / 26.04。' >&2; return 1;
  }
  arch="$(uname -m)"
  case "$arch" in
    x86_64) node_arch=x64; node_hash=48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75 ;;
    aarch64|arm64) node_arch=arm64; node_hash=eb187837a2230d4047161ac0be008584e16b46f726e9c9490ee35dc6b17d9ba8 ;;
    *) echo '当前支持 AMD64 / ARM64。' >&2; return 1 ;;
  esac
  # Collect and check installation input before downloading the toolchain.
  python3 "$work/source/rewrite/deploy/install-experimental.py" --experimental --role "$role" \
    --source "$work/source" --commit "$revision" --check "${args[@]}"
  printf '安装构建依赖；首次构建需要下载 Rust、Node.js 和项目依赖。\n'
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev ca-certificates curl git python3 xz-utils
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 180 \
    "https://nodejs.org/dist/v$node_version/node-v$node_version-linux-$node_arch.tar.xz" -o "$work/node.tar.xz"
  printf '%s  %s\n' "$node_hash" "$work/node.tar.xz" | sha256sum -c -
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 180 \
    https://sh.rustup.rs -o "$work/rustup.sh"
  mkdir "$work/node" "$work/cache"
  tar -xJf "$work/node.tar.xz" -C "$work/node" --strip-components=1
  chown -R nobody:nogroup "$work"
  runuser -u nobody -- env CARGO_HOME="$work/cargo" RUSTUP_HOME="$work/rustup" \
    sh "$work/rustup.sh" -y --profile minimal --default-toolchain 1.99.1 --no-modify-path
  runuser -u nobody -- env CARGO_HOME="$work/cargo" RUSTUP_HOME="$work/rustup" \
    npm_config_cache="$work/cache" PATH="$work/node/bin:$work/cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    bash "$work/source/rewrite/build-release.sh" "$work/release"
  chown root:root "$work"
  chown -R root:root "$work/source" "$work/release" "$work/node"
  python3 "$work/source/rewrite/deploy/install-experimental.py" --experimental --role "$role" \
    --source "$work/source" --commit "$revision" --release-dir "$work/release" --node-bin "$work/node/bin/node" "${args[@]}"
}
main "$@"
