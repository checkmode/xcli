#!/usr/bin/env bash
# Build the experimental Rust/TypeScript bundle from this checkout.
set -euo pipefail
if [[ $# != 1 || "${1:-}" == --help ]]; then
  echo '用法：bash rewrite/build-release.sh 输出目录'
  echo '需要 Linux、Rust/Cargo、Node.js 24–26 和 npm。输出是实验版本，尚不能用于生产。'
  [[ $# == 1 ]] && exit 0 || exit 2
fi
[[ "$(uname -s)" == Linux ]] || { echo '需要在 Linux 上构建。' >&2; exit 1; }
for tool in cargo node npm; do command -v "$tool" >/dev/null || { echo "缺少构建工具：$tool" >&2; exit 1; }; done
node -e 'const n=Number(process.versions.node.split(".")[0]); if(n<24||n>=27)process.exit(1)' || { echo '需要 Node.js 24–26。' >&2; exit 1; }
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
output="$1"
[[ ! -e "$output" && ! -L "$output" ]] || { echo '输出目录已存在，请指定新目录。' >&2; exit 1; }
mkdir -p -- "$(dirname -- "$output")"
work="$(mktemp -d "${TMPDIR:-/tmp}/xcli-rust-release.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
printf '构建 Rust 后端…\n'
(cd "$root/rust" && cargo build --locked --release --workspace --bins)
printf '构建 Node.js 网关和 Vue 页面…\n'
(cd "$root/web" && npm ci --no-audit --no-fund && npm run build)
mkdir -p "$work/release/bin" "$work/release/web" "$work/release/deploy"
for binary in xcli-cert-renew xcli-host-disk-probe xcli-import-probe xcli-import-service \
  xcli-monitor-service xcli-node-service xcli-panel-checkpoint xcli-panel-init xcli-panel-service xcli-webhook-sender xcli-webshare-service; do
  install -m 0755 "$root/rust/target/release/$binary" "$work/release/bin/$binary"
done
cp -R "$root/web/dist/." "$work/release/web/"
printf '{"type":"module"}\n' > "$work/release/web/package.json"
cp -R "$root/deploy/." "$work/release/deploy/"
printf 'experimental\n' > "$work/release/BUILD_STATUS"
mv -- "$work/release" "$output"
printf '实验版本已构建：%s\n' "$output"
printf '尚未包含 Xray、Node.js 运行时或完整安装器；不要直接部署到生产。\n'
