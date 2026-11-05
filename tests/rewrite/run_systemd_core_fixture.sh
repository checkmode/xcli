#!/usr/bin/env bash
# Start only temporary systemd units in a private network namespace.
set -euo pipefail
if [[ "$EUID" != 0 || "$#" != 3 ]]; then
  echo 'usage: sudo bash run_systemd_core_fixture.sh REPO UNPRIVILEGED_USER XRAY' >&2
  exit 2
fi
repo="$1" user="$2" xray="$3"
panel_binary="${XCLI_TEST_PANEL_BIN:-$repo/rewrite/rust/target/debug/xcli-panel-service}"
panel_init="${XCLI_TEST_PANEL_INIT:-$repo/rewrite/rust/target/debug/xcli-panel-init}"
[[ "$(id -u "$user")" != 0 && -x "$xray" ]]
[[ -x "$panel_binary" && -x "$panel_init" ]]
if [[ "$(systemctl show xcli-core.service -p LoadState --value)" != not-found ]]; then
  echo 'xcli-core.service already exists; refusing to replace it' >&2
  exit 2
fi
fixture="$(mktemp -d /var/lib/xcli-systemd-fixture.XXXXXXXX)"
panel_unit="xcli-fixture-panel-$(basename "$fixture").service"
net_unit="xcli-fixture-net-$(basename "$fixture").service"
core_started=0 panel_started=0 net_started=0
cleanup() {
  if ((panel_started)); then systemctl stop "$panel_unit" || true; systemctl reset-failed "$panel_unit" 2>/dev/null || true; fi
  if ((core_started)); then systemctl stop xcli-core.service || true; systemctl reset-failed xcli-core.service 2>/dev/null || true; fi
  if ((net_started)); then systemctl stop "$net_unit" || true; systemctl reset-failed "$net_unit" 2>/dev/null || true; fi
  [[ "$fixture" == /var/lib/xcli-systemd-fixture.* ]] && rm -rf -- "$fixture"
}
trap cleanup EXIT
chmod 0755 "$fixture"
cp "$panel_binary" "$fixture/xcli-panel-service"
cp "$xray" "$fixture/xray"
xray="$fixture/xray"
python3 - "$fixture" <<'PY'
import json,os,pathlib,sys
p=pathlib.Path(sys.argv[1])
core={'log':{'loglevel':'warning','access':'none'},
  'api':{'tag':'api','listen':'127.0.0.1:10085','services':['HandlerService','StatsService']},
  'stats':{},'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}},
  'inbounds':[{'tag':'websocket','listen':'127.0.0.1','port':10080,'protocol':'vless',
    'settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'ws','wsSettings':{'path':'/fixture'}}}],
  'outbounds':[{'tag':'direct','protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}}]}
(p/'core.json').write_text(json.dumps(core))
(p/'settings.json').write_text(json.dumps({'origin':'https://testserver','domain':'testserver',
  'public_ip':'203.0.113.2','reality_sni':'www.bing.com','reality_public':'p'*43,
  'short_id':'0123456789abcdef','ws_path':'/fixture'}))
(p/'security.key').write_bytes(os.urandom(32))
os.chmod(p/'security.key',0o600)
PY
chown -R "$user" "$fixture"
chown root:root "$fixture/xray" "$fixture/xcli-panel-service"
printf 'fixture-password-123\n' | runuser -u "$user" -- "$panel_init" \
  --experimental --database "$fixture/gateway.sqlite"
systemd-run --unit="$net_unit" --property=PrivateNetwork=yes /usr/bin/sleep 180
net_started=1
systemd-run --unit=xcli-core.service --property="User=$user" --property="Group=$(id -gn "$user")" \
  --property=PrivateNetwork=yes --property="JoinsNamespaceOf=$net_unit" --property=NoNewPrivileges=yes --property=PrivateTmp=yes \
  --property=ProtectSystem=strict --property=ProtectHome=yes \
  --property=CapabilityBoundingSet=CAP_NET_BIND_SERVICE --property=AmbientCapabilities=CAP_NET_BIND_SERVICE \
  --property=Restart=always --property=RestartSec=1 --property=StartLimitIntervalSec=0 \
  "$xray" run -config "$fixture/core.json"
core_started=1
systemd-run --unit="$panel_unit" --property="User=$user" --property="Group=$(id -gn "$user")" \
  --property=PrivateNetwork=yes --property="JoinsNamespaceOf=$net_unit" \
  --property=NoNewPrivileges=yes --property=PrivateTmp=yes --property=ProtectSystem=strict \
  --property=ProtectHome=yes --property="ReadWritePaths=$fixture" --property=CapabilityBoundingSet= \
  "$fixture/xcli-panel-service" --experimental \
  --db "$fixture/gateway.sqlite" --secret-key "$fixture/security.key" --settings "$fixture/settings.json" \
  --origin https://testserver --port 18080 --core-binary "$xray" --core-api 127.0.0.1:10085 \
  --core-pid-file /sys/fs/cgroup/system.slice/xcli-core.service/cgroup.procs --core-tags websocket --core-poll-seconds 1
panel_started=1
panel_pid="$(systemctl show "$panel_unit" -p MainPID --value)"
[[ "$panel_pid" =~ ^[1-9][0-9]*$ ]]
if ! XCLI_TEST_SYSTEMD_FIXTURE="$fixture" XCLI_TEST_XRAY="$xray" \
  nsenter -t "$panel_pid" -n /usr/bin/python3 "$repo/tests/rewrite/test_systemd_core_fixture.py"; then
  journalctl -u "$panel_unit" -u xcli-core.service -n 40 --no-pager || true
  exit 1
fi
