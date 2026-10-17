#!/usr/bin/env bash
# Upgrade a provisioned 1.1+ gateway without changing identities or restarting its data plane.
set -euo pipefail
# Historical migration only; never overwrite a managed application release.
if [[ -L /opt/xcli/current ]]; then
    echo '部署已纳入完整版本管理；请使用 update.sh 或 xcli-release。' >&2
    exit 1
fi
[[ $EUID == 0 && $# == 3 ]] || { echo 'Usage: sudo upgrade-operations.sh SOURCE_DIR VERIFIED_BINARY NEW_ROOT_BACKUP_DIR'; exit 1; }
source_dir=$(realpath -- "$1")
candidate=$(realpath -- "$2")
backup=$3
current=/usr/local/lib/xray-gateway/panel-current
dropdir=/etc/systemd/system/xray-gateway-panel.service.d
[[ -x "$candidate" && -L "$current" && "$backup" == /root/* && ! -e "$backup" && -d "$dropdir" ]] || exit 1
[[ -f "$source_dir/static/operations.js" && -f /etc/xray-gateway/security.key && -f /etc/xcli-monitor/monitor.json ]] || exit 1
[[ $("$candidate" --version) == *'1.2.0'* ]] || { echo 'Expected a verified 1.2.0 candidate'; exit 1; }
[[ $("$current" --version) == *'1.1.0'* || $("$current" --version) == *'1.2.0'* ]] || { echo 'Upgrade to an MFA-compatible 1.1+ panel first'; exit 1; }
previous=$(readlink -f "$current")
[[ "$previous" != "$candidate" ]] || { echo 'Candidate is already selected'; exit 1; }
for service in xray-gateway-panel xray-gateway-core xray-gateway-monitor nginx; do systemctl is-active --quiet "$service"; done
install -d -m700 "$backup"
python3 "$source_dir/cpp/tests/migration_state.py" save "$backup/state.json"
# Back up before the candidate opens the database and creates its additive tables.
"$current" --backup "$backup/gateway.sqlite"
cp -a /etc/xray-gateway "$backup/config"
cp -a /etc/xcli-monitor "$backup/monitor-config"
cp -a "$dropdir" "$backup/dropins"
printf '%s\n' "$previous" > "$backup/previous-target.txt"
systemctl show xray-gateway-core xray-gateway-monitor nginx -p Id -p MainPID -p NRestarts > "$backup/processes-before.txt"
runuser -u xgateway -g xgateway -G xgmonitor -- "$candidate" \
  --secret-key /etc/xray-gateway/security.key --monitor-config /etc/xcli-monitor/monitor.json \
  --preflight > "$backup/preflight.json"
python3 - "$backup/preflight.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))
assert value['database_integrity']=='ok', 'Database integrity failed'
assert value['pending_revocations']==0 and value['pending_additions']==0, 'Core identities would change; deployment stopped'
print('Preflight: database valid; no core identity changes required')
PY
cat > "$backup/rollback.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || exit 1
backup=$(cd -- "$(dirname -- "$0")" && pwd)
current=/usr/local/lib/xray-gateway/panel-current
dropdir=/etc/systemd/system/xray-gateway-panel.service.d
previous=$(cat "$backup/previous-target.txt")
[[ -x "$previous" ]] || exit 1
# Both releases support MFA. Retain the live database, including new users and accumulated traffic.
rm -f "$dropdir/40-operations.conf"
cp -a "$backup/dropins/." "$dropdir/"
ln -s "$previous" "${current}.rollback.$$"
mv -Tf "${current}.rollback.$$" "$current"
systemctl daemon-reload
systemctl restart xray-gateway-panel
curl --noproxy '*' -fsS --retry 10 --retry-connrefused --retry-delay 1 --max-time 2 http://127.0.0.1:8080/healthz >/dev/null
echo 'Previous compatible panel restored; current users, MFA and traffic retained. Core, monitor and Nginx were not restarted.'
SH
chmod 700 "$backup/rollback.sh"
switched=0
finish() { result=$?; if [[ $result != 0 && $switched == 1 ]]; then "$backup/rollback.sh"; fi; exit "$result"; }
trap finish EXIT
release_dir=$(dirname -- "$candidate")
[[ ! -e "$release_dir/static" ]] || { echo 'Use a fresh release directory'; exit 1; }
install -d -m755 "$release_dir/static"
install -m644 "$source_dir/static/"* "$release_dir/static/"
switched=1
printf '[Service]\nEnvironment=XG_STATIC=%s/static\n' "$release_dir" > "$dropdir/40-operations.conf"
ln -s "$candidate" "${current}.next.$$"
mv -Tf "${current}.next.$$" "$current"
systemctl daemon-reload
systemctl restart xray-gateway-panel
curl --noproxy '*' -fsS --retry 15 --retry-connrefused --retry-delay 1 --max-time 2 http://127.0.0.1:8080/healthz >/dev/null
python3 "$source_dir/cpp/tests/migration_state.py" verify "$backup/state.json"
systemctl show xray-gateway-core xray-gateway-monitor nginx -p Id -p MainPID -p NRestarts > "$backup/processes-after.txt"
cmp "$backup/processes-before.txt" "$backup/processes-after.txt"
date -u +'%Y-%m-%dT%H:%M:%SZ operations upgrade completed'
echo "Users, subscriptions, MFA and data-plane processes preserved; rollback: $backup/rollback.sh"
switched=0
