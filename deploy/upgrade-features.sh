#!/usr/bin/env bash
# Upgrade an already provisioned gateway. Does not rewrite settings or restart Xray/Nginx.
set -euo pipefail
# Historical migration only; never overwrite a managed application release.
if [[ -L /opt/xcli/current ]]; then
    echo '部署已纳入完整版本管理；请使用 update.sh 或 xcli-release。' >&2
    exit 1
fi
[[ $EUID == 0 && $# == 3 ]] || { echo 'Usage: sudo upgrade-features.sh SOURCE_DIR VERIFIED_BINARY NEW_ROOT_BACKUP_DIR'; exit 1; }
source_dir=$(realpath -- "$1")
candidate=$(realpath -- "$2")
backup=$3
[[ -x "$candidate" && "$backup" == /root/* && ! -e "$backup" && -f "$source_dir/static/index.html" ]] || exit 1
state=/var/lib/xray-gateway
base=/etc/xray-gateway
current=/usr/local/lib/xray-gateway/panel-current
dropdir=/etc/systemd/system/xray-gateway-panel.service.d
core_pid=$(systemctl show xray-gateway-core -p MainPID --value)
[[ "$core_pid" -gt 1 && -L "$current" ]] || { echo 'Running provisioned C++ gateway required'; exit 1; }
install -d -m700 "$backup"
python3 "$source_dir/cpp/tests/migration_state.py" save "$backup/state.json"
"$candidate" --backup "$backup/gateway.sqlite"
cp -a "$dropdir" "$backup/dropins"
cp -a /opt/xray-gateway/static "$backup/static"
readlink -f "$current" > "$backup/previous-target.txt"
systemctl show xray-gateway-core nginx -p Id -p MainPID -p NRestarts > "$backup/processes-before.txt"

# Probe uses a separate UID: the proxy's private-network firewall stays intact.
getent group xgmonitor >/dev/null || groupadd --system xgmonitor
getent passwd xgprobe >/dev/null || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid xgmonitor xgprobe
usermod -g xgmonitor xgprobe
install -d -o root -g xgmonitor -m750 /etc/xcli-monitor
install -d -o xgprobe -g xgmonitor -m750 /var/lib/xray-gateway-monitor
python3 - <<'PY'
import grp,json,os,pathlib,secrets,uuid
base=pathlib.Path('/etc/xray-gateway');group=grp.getgrnam('xgateway').gr_gid
key=base/'security.key'
if not key.exists():
    fd=os.open(key,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o640)
    with os.fdopen(fd,'wb') as f:f.write(secrets.token_bytes(32))
os.chown(key,0,group);os.chmod(key,0o640)
config=pathlib.Path('/etc/xcli-monitor/monitor.json')
# Preserve a probe identity created by an early deployment.
if not config.exists() and (base/'monitor.json').exists():
    config.write_bytes((base/'monitor.json').read_bytes())
if not config.exists():
    settings=json.loads((base/'settings.json').read_text())
    value={k:settings[k] for k in ['domain','public_ip','reality_sni','reality_public','short_id','ws_path']}
    value['uuid']=str(uuid.uuid4())
    fd=os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o640)
    with os.fdopen(fd,'w') as f:json.dump(value,f)
os.chown(config,0,grp.getgrnam('xgmonitor').gr_gid);os.chmod(config,0o640)
PY
runuser -u xgateway -g xgateway -G xgmonitor -- "$candidate" --secret-key "$base/security.key" --monitor-config /etc/xcli-monitor/monitor.json --preflight > "$backup/preflight.json"
python3 - "$backup/preflight.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x['database_integrity']=='ok' and x['pending_revocations']==0 and x['pending_additions'] in (0,2), 'Unexpected core reconciliation; deployment stopped'
print('Preflight: existing identities match; only dedicated probe additions are permitted')
PY
cat > "$backup/rollback.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || exit 1
backup=$(cd -- "$(dirname -- "$0")" && pwd)
python3 - <<'PY'
import sqlite3
with sqlite3.connect('file:/var/lib/xray-gateway/gateway.sqlite?mode=ro',uri=True) as db:
    if db.execute('SELECT enabled FROM mfa WHERE id=1').fetchone()[0]:
        raise SystemExit('Rollback refused: previous backend cannot enforce enabled MFA. Use a compatible release.')
PY
systemctl stop xray-gateway-monitor 2>/dev/null || true
systemctl stop xray-gateway-panel
cp -a "$backup/static/." /opt/xray-gateway/static/
rm -f /etc/systemd/system/xray-gateway-panel.service.d/30-features.conf
cp -a "$backup/dropins/." /etc/systemd/system/xray-gateway-panel.service.d/
ln -sfn -- "$(cat "$backup/previous-target.txt")" /usr/local/lib/xray-gateway/panel-current
systemctl daemon-reload
systemctl start xray-gateway-panel
# Old controllers may revoke the dedicated probe and reconnect clients once.
echo 'Previous panel restored; current user database retained. Core may reconnect once to remove probe identity.'
SH
chmod 700 "$backup/rollback.sh"
switched=0
finish() { result=$?; if [[ $result != 0 && $switched == 1 ]]; then "$backup/rollback.sh"; fi; exit "$result"; }
trap finish EXIT
install -d -m755 /opt/xray-gateway/scripts
install -m644 "$source_dir/scripts/probe.py" /opt/xray-gateway/scripts/probe.py
install -m644 "$source_dir/scripts/gatewayctl.py" /opt/xray-gateway/scripts/gatewayctl.py
install -m644 "$source_dir/deploy/xray-gateway-monitor.service" /etc/systemd/system/xray-gateway-monitor.service
install -d -m755 "$dropdir"
cat > "$dropdir/30-features.conf" <<'CONF'
[Service]
Environment=XG_SECRET_KEY=/etc/xray-gateway/security.key
SupplementaryGroups=xgmonitor
Environment=XG_MONITOR_CONFIG=/etc/xcli-monitor/monitor.json
Environment=XG_MONITOR_REPORT=/var/lib/xray-gateway-monitor/report.json
Environment=XG_BACKUP_INTERVAL=21600
Environment=XG_BACKUP_RETENTION=28
CONF
# Static paths switch with the same release as the executable.
release_dir=$(dirname -- "$candidate")
install -d -m755 "$release_dir/static"
install -m644 "$source_dir/static/"* "$release_dir/static/"
printf 'Environment=XG_STATIC=%s/static\n' "$release_dir" >> "$dropdir/30-features.conf"
switched=1
ln -s "$candidate" "${current}.next.$$"
mv -Tf "${current}.next.$$" "$current"
systemctl daemon-reload
systemctl restart xray-gateway-panel
for attempt in $(seq 1 60); do
  if curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:8080/healthz >/dev/null; then break; fi
  sleep 0.25
done
curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null
[[ $(systemctl show xray-gateway-core -p MainPID --value) == "$core_pid" ]] || { echo 'Core PID unexpectedly changed'; exit 1; }
python3 "$source_dir/cpp/tests/migration_state.py" verify "$backup/state.json"
systemctl enable --now xray-gateway-monitor
systemctl show xray-gateway-core nginx -p Id -p MainPID -p NRestarts > "$backup/processes-after.txt"
date -u +'%Y-%m-%dT%H:%M:%SZ feature upgrade completed'
echo "Core PID retained: $core_pid; recovery directory: $backup"
switched=0
