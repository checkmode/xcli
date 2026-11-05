#!/usr/bin/env bash
# Upgrade a legacy panel using the checked-out Git revision.
set -euo pipefail

main() {
  local root revision build_revision work node_arch node_hash node_version=24.22.2 release node
  root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  [[ $EUID == 0 ]] || { echo '请使用 sudo bash ./upgrade.sh。' >&2; return 1; }
  [[ $# -le 1 ]] || { echo '用法：sudo bash ./upgrade.sh [--check]' >&2; return 1; }
  if [[ ${1:-} == --check ]]; then
    python3 "$root/rewrite/deploy/upgrade-legacy.py" --check
    return
  fi
  [[ $# == 0 ]] || { echo '用法：sudo bash ./upgrade.sh [--check]' >&2; return 1; }
  revision="$(git -c safe.directory="$root" -C "$root" rev-parse HEAD)"
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo '无法读取 Git 提交。' >&2; return 1; }
  if [[ -f /etc/systemd/system/xcli-panel.service ]]; then
    if [[ -f /opt/xcli/current/COMMIT && $(cat /opt/xcli/current/COMMIT) == "$revision" ]]; then
      echo '当前版本已经安装。'
      return
    fi
    echo '检测到新版面板；新版之间的更新暂不由此脚本处理。' >&2
    return 1
  fi
  python3 "$root/rewrite/deploy/upgrade-legacy.py" --check
  build_revision="${XCLI_UPGRADE_BUILD_REVISION:-$revision}"
  [[ "$build_revision" =~ ^[0-9a-f]{40}$ ]] || { echo '构建版本无效。' >&2; return 1; }
  if [[ "$build_revision" != "$revision" ]]; then
    git -c safe.directory="$root" -C "$root" diff --quiet "$build_revision" "$revision" -- rewrite/rust rewrite/web || {
      echo '预构建程序与当前源码不一致。' >&2; return 1;
    }
  fi
  if [[ -n "${XCLI_UPGRADE_RELEASE:-}" && -n "${XCLI_UPGRADE_NODE:-}" ]]; then
    release="$XCLI_UPGRADE_RELEASE"
    node="$XCLI_UPGRADE_NODE"
  else
    [[ -z "${XCLI_UPGRADE_RELEASE:-}${XCLI_UPGRADE_NODE:-}" ]] || { echo '构建结果不完整。' >&2; return 1; }
    case "$(uname -m)" in
      x86_64) node_arch=x64; node_hash=48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75 ;;
      aarch64|arm64) node_arch=arm64; node_hash=eb187837a2230d4047161ac0be008584e16b46f726e9c9490ee35dc6b17d9ba8 ;;
      *) echo '当前支持 AMD64 / ARM64。' >&2; return 1 ;;
    esac
    work="$(mktemp -d /var/tmp/xcli-upgrade-build.XXXXXXXX)"
    trap "rm -rf -- '$work'" EXIT
    chmod 0755 "$work"
    mkdir "$work/source" "$work/cache" "$work/node"
    git -c safe.directory="$root" -C "$root" archive "$revision" | tar -x -C "$work/source"
    echo '正在安装构建依赖并构建新版，原有服务继续运行。'
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential pkg-config libssl-dev ca-certificates curl git python3 python3-cryptography xz-utils
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 180 \
      "https://nodejs.org/dist/v$node_version/node-v$node_version-linux-$node_arch.tar.xz" -o "$work/node.tar.xz"
    printf '%s  %s\n' "$node_hash" "$work/node.tar.xz" | sha256sum -c -
    tar -xJf "$work/node.tar.xz" -C "$work/node" --strip-components=1
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 180 \
      https://sh.rustup.rs -o "$work/rustup.sh"
    chown -R nobody:nogroup "$work"
    runuser -u nobody -- env CARGO_HOME="$work/cargo" RUSTUP_HOME="$work/rustup" \
      sh "$work/rustup.sh" -y --profile minimal --default-toolchain 1.99.1 --no-modify-path
    runuser -u nobody -- env CARGO_HOME="$work/cargo" RUSTUP_HOME="$work/rustup" CARGO_BUILD_JOBS=2 \
      npm_config_cache="$work/cache" PATH="$work/node/bin:$work/cargo/bin:/usr/local/bin:/usr/bin:/bin" \
      nice -n 10 bash "$work/source/rewrite/build-release.sh" "$work/release"
    release="$work/release"
    node="$work/node/bin/node"
  fi
  python3 "$root/rewrite/deploy/upgrade-legacy.py" --release-dir "$release" --node-bin "$node" --revision "$revision"
}
main "$@"
