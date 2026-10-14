#!/usr/bin/env bash
# Same-schema 1.3.0 update; preserve Xray/Nginx and never restore an old database.
set -euo pipefail
[[ $EUID == 0 && $# == 2 && "$2" =~ ^[0-9a-f]{40}$ ]] || exit 1
source_dir=$(realpath -- "$1")
revision=$2
current=/usr/local/lib/xray-gateway/panel-current
dropdir=/etc/systemd/system/xray-gateway-panel.service.d
dropin=$dropdir/70-update.conf
[[ -L "$current" && -d "$dropdir" && -f "$source_dir/static/runtime.js" ]] || exit 1
[[ $("$current" --version) == 'xray-gateway-panel 1.3.0 (C++20)' ]] || exit 1
backup=$(mktemp -d /root/xcli-update-XXXXXXXX)
chmod 700 "$backup"
exec > >(tee -a "$backup/update.log") 2>&1
echo "更新日志与回退目录：$backup"
previous=$(readlink -f "$current")
printf '%s\n' "$previous" > "$backup/previous-target.txt"
[[ ! -e "$dropin" ]] || cp -a "$dropin" "$backup/previous-update.conf"
systemctl show xray-gateway-core xray-gateway-monitor nginx -p Id -p MainPID -p NRestarts > "$backup/processes-before.txt"
packages=(g++ cmake ninja-build pkg-config libcpp-httplib-dev nlohmann-json3-dev libsqlite3-dev libssl-dev libcurl4-openssl-dev libqrencode-dev libpng-dev libgrpc++-dev libprotobuf-dev protobuf-compiler protobuf-compiler-grpc)
missing=()
for package in "${packages[@]}"; do
    [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) == 'install ok installed' ]] || missing+=("$package")
done
if ((${#missing[@]})); then
    apt-get update
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y --no-install-recommends --no-upgrade "${missing[@]}"
fi
build_dir=$(dirname -- "$source_dir")/build
install -d -o xgateway -g xgateway -m755 "$build_dir"
runuser -u xgateway -- env XG_SOURCE_REVISION="${revision:0:12}" bash "$source_dir/deploy/build-cpp.sh" "$build_dir"
candidate=$build_dir/xray-gateway-panel
[[ $("$candidate" --version) == 'xray-gateway-panel 1.3.0 (C++20)' ]] || { echo '候选版本不兼容。'; exit 1; }
python3 "$source_dir/cpp/tests/migration_state.py" save "$backup/state.json"
"$current" --backup "$backup/gateway.sqlite"
cp -a /etc/xray-gateway "$backup/config"
webshare_update=0
if [[ -f /etc/systemd/system/xray-gateway-webshare.service ]]; then
    [[ -f /opt/xray-gateway/scripts/webshare.py && -f "$source_dir/scripts/webshare.py" && -f "$source_dir/deploy/xray-gateway-webshare.service" ]] || exit 1
    python3 - "$source_dir/scripts/webshare.py" <<'PY'
import pathlib,sys
compile(pathlib.Path(sys.argv[1]).read_bytes(),sys.argv[1],'exec')
PY
    if ! cmp -s /opt/xray-gateway/scripts/webshare.py "$source_dir/scripts/webshare.py" || ! cmp -s /etc/systemd/system/xray-gateway-webshare.service "$source_dir/deploy/xray-gateway-webshare.service"; then
        cp -a /opt/xray-gateway/scripts/webshare.py "$backup/previous-webshare.py"
        cp -a /etc/systemd/system/xray-gateway-webshare.service "$backup/previous-webshare.service"
        webshare_update=1
    fi
fi
runuser -u xgateway -g xgateway -G xgmonitor -- "$candidate" \
    --secret-key /etc/xray-gateway/security.key --monitor-config /etc/xcli-monitor/monitor.json \
    --preflight > "$backup/preflight.json"
python3 - "$backup/preflight.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))
assert value['database_integrity']=='ok', 'Database integrity failed'
assert value['pending_revocations']==0 and value['pending_additions']==0, 'Core identities would change; stopped'
print('数据库正常；无需更改核心账号。')
PY
cat > "$backup/rollback.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || exit 1
backup=$(cd -- "$(dirname -- "$0")" && pwd)
python3 - "$backup/state.json" <<'PY'
import hashlib,json,pathlib,sys
expected=json.load(open(sys.argv[1]))['settings_digest']
actual=hashlib.sha256(pathlib.Path('/etc/xray-gateway/settings.json').read_bytes()).hexdigest()
if actual!=expected:
    raise SystemExit('服务器配置已变化；请先回退对应功能配置，再回退旧面板。当前服务保持原状。')
PY
current=/usr/local/lib/xray-gateway/panel-current
dropin=/etc/systemd/system/xray-gateway-panel.service.d/70-update.conf
previous=$(cat "$backup/previous-target.txt")
[[ -x "$previous" ]] || exit 1
if [[ -f "$backup/previous-update.conf" ]]; then
    cp -a "$backup/previous-update.conf" "$dropin"
else
    rm -f -- "$dropin"
fi
ln -s "$previous" "${current}.rollback.$$"
mv -Tf "${current}.rollback.$$" "$current"
if [[ -f "$backup/previous-webshare.py" ]]; then
    cp -a "$backup/previous-webshare.py" /opt/xray-gateway/scripts/webshare.py
    cp -a "$backup/previous-webshare.service" /etc/systemd/system/xray-gateway-webshare.service
fi
systemctl daemon-reload
if [[ -f "$backup/previous-webshare.py" ]]; then systemctl restart xray-gateway-webshare; fi
systemctl restart xray-gateway-panel
curl --noproxy '*' -fsS --retry 15 --retry-connrefused --retry-delay 1 --max-time 2 http://127.0.0.1:8080/healthz >/dev/null
echo '旧面板已恢复；当前数据库、用户和累计流量保留。'
SH
chmod 700 "$backup/rollback.sh"
switched=0
finish() { result=$?; if [[ $result != 0 && $switched == 1 ]]; then "$backup/rollback.sh"; fi; exit "$result"; }
trap finish EXIT
release=$(mktemp -d "/usr/local/lib/xray-gateway/releases/cpp-1.3.0-${revision:0:12}-XXXXXXXX")
chmod 755 "$release"
install -m755 "$candidate" "$release/xray-gateway-panel"
install -d -m755 "$release/static"
install -m644 "$source_dir/static/"* "$release/static/"
printf '%s\n' "$revision" > "$release/revision.txt"
chmod 644 "$release/revision.txt"
switched=1
printf '[Service]\nEnvironment=XG_STATIC=%s/static\n' "$release" > "$dropin"
chmod 644 "$dropin"
ln -s "$release/xray-gateway-panel" "${current}.next.$$"
mv -Tf "${current}.next.$$" "$current"
if [[ $webshare_update == 1 ]]; then
    install -m644 "$source_dir/scripts/webshare.py" /opt/xray-gateway/scripts/webshare.py
    install -m644 "$source_dir/deploy/xray-gateway-webshare.service" /etc/systemd/system/xray-gateway-webshare.service
fi
systemctl daemon-reload
if [[ $webshare_update == 1 ]]; then
    systemctl restart xray-gateway-webshare
    systemctl is-active --quiet xray-gateway-webshare
fi
systemctl restart xray-gateway-panel
curl --noproxy '*' -fsS --retry 15 --retry-connrefused --retry-delay 1 --max-time 2 http://127.0.0.1:8080/healthz >/dev/null
panel_pid=$(systemctl show xray-gateway-panel -p MainPID --value)
[[ $(readlink -f "/proc/$panel_pid/exe") == "$release/xray-gateway-panel" ]] || { echo '面板未运行候选程序。'; exit 1; }
python3 "$source_dir/cpp/tests/migration_state.py" verify "$backup/state.json"
systemctl show xray-gateway-core xray-gateway-monitor nginx -p Id -p MainPID -p NRestarts > "$backup/processes-after.txt"
cmp "$backup/processes-before.txt" "$backup/processes-after.txt"
switched=0
echo "更新完成：$revision；核心、探测服务和 Nginx 进程保持原状。"
echo "回退：sudo bash $backup/rollback.sh"
