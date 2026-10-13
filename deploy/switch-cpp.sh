#!/usr/bin/env bash
# Switch only the management service; keep the Xray and Nginx processes running.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo'; exit 1; }
[[ $# == 2 ]] || { echo 'Usage: switch-cpp.sh VERIFIED_BINARY BACKUP_DIRECTORY'; exit 1; }
candidate=$(realpath -- "$1")
backup=$2
[[ -x "$candidate" && "$backup" == /root/* && ! -e "$backup" ]] || { echo 'Invalid candidate or backup path'; exit 1; }
unit=xray-gateway-panel.service
dropin=/etc/systemd/system/xray-gateway-panel.service.d/20-cpp-backend.conf
current=/usr/local/lib/xray-gateway/panel-current
scripts=/opt/xray-gateway/cpp/tests
core_pid=$(systemctl show xray-gateway-core -p MainPID --value)
[[ "$core_pid" -gt 1 ]] || { echo 'Core is not running'; exit 1; }
install -d -m700 "$backup"
cp -a /etc/systemd/system/xray-gateway-panel.service "$backup/panel.service"
[[ ! -e "$dropin" ]] || cp -a "$dropin" "$backup/previous-dropin.conf"
[[ ! -L "$current" ]] || readlink "$current" > "$backup/previous-target.txt"
cp -a /opt/xray-gateway/app.py "$backup/legacy-app.py"
python3 "$scripts/migration_state.py" save "$backup/state.json"
sudo -u xgateway "$candidate" --preflight > "$backup/preflight.json"
python3 - "$backup/preflight.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x['database_integrity']=='ok' and x['pending_additions']==0 and x['pending_revocations']==0, 'Pending reconciliation; do not switch yet'
print('Preflight: existing core users match the database')
PY
"$candidate" --backup "$backup/gateway.sqlite"

cat > "$backup/rollback.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo'; exit 1; }
backup=$(cd -- "$(dirname -- "$0")" && pwd)
dropin=/etc/systemd/system/xray-gateway-panel.service.d/20-cpp-backend.conf
systemctl stop xray-gateway-panel
if [[ -e "$backup/previous-dropin.conf" ]]; then
  install -m644 "$backup/previous-dropin.conf" "$dropin"
else
  rm -f -- "$dropin"
fi
if [[ -e "$backup/previous-target.txt" ]]; then
  ln -sfn -- "$(cat "$backup/previous-target.txt")" /usr/local/lib/xray-gateway/panel-current
fi
systemctl daemon-reload
systemctl start xray-gateway-panel
echo 'Previous management backend restored; database and Xray were retained.'
SH
chmod 700 "$backup/rollback.sh"
switched=0
rollback_on_error() {
  result=$?
  if [[ "$result" != 0 && "$switched" == 1 ]]; then "$backup/rollback.sh"; fi
  exit "$result"
}
trap rollback_on_error EXIT

# Write the drop-in and link before stopping Python; daemon-reload does not restart it.
switched=1
install -d -m755 "$(dirname -- "$dropin")"
printf '[Unit]\nDescription=Xdistribute C++ management panel\n[Service]\nExecStart=\nExecStart=%s\nTimeoutStopSec=30\n' "$current" > "$dropin"
chmod 644 "$dropin"
ln -s "$candidate" "${current}.next.$$"
mv -Tf "${current}.next.$$" "$current"
systemctl daemon-reload
date -u +'%Y-%m-%dT%H:%M:%SZ stopping management service'
systemctl restart "$unit"
for attempt in $(seq 1 40); do
  if curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:8080/healthz > /dev/null; then break; fi
  sleep 0.25
done
curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:8080/healthz > /dev/null
[[ $(systemctl show xray-gateway-core -p MainPID --value) == "$core_pid" ]] || { echo 'Core PID changed'; exit 1; }
panel_pid=$(systemctl show "$unit" -p MainPID --value)
[[ $(readlink -f "/proc/$panel_pid/exe") == "$candidate" ]] || { echo 'Unexpected management executable'; exit 1; }
python3 "$scripts/migration_state.py" verify "$backup/state.json"
date -u +'%Y-%m-%dT%H:%M:%SZ C++ management service ready'
echo "Core PID retained: $core_pid; management PID: $panel_pid"
echo "Rollback: $backup/rollback.sh"
switched=0
