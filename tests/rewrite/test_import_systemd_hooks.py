"""Test the experimental service-switch order in a disposable root fixture."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest

BINARY = os.environ.get('XCLI_SWITCH_FIXTURE', '')
UID = int(os.environ.get('XCLI_TEST_REPORT_UID', '0'))
GID = int(os.environ.get('XCLI_TEST_REPORT_GID', '0'))


@unittest.skipUnless(os.geteuid() == 0 and UID and GID and BINARY and Path(BINARY).is_file(),
                     'requires root, an unprivileged fixture account and switch fixture')
class SwitchHooks(unittest.TestCase):
    def test_checkpoint_precedes_core_stop_and_failure_restores_panel(self):
        with tempfile.TemporaryDirectory(prefix='xcli-switch-fixture-', dir='/var/lib') as folder:
            root=Path(folder);root.chmod(0o755)
            trace=root/'trace';trace.write_text('');trace.chmod(0o666)
            active=root/'active';active.touch();failure=root/'fail-checkpoint'
            systemctl=root/'systemctl'
            systemctl.write_text(f'''#!/bin/sh
printf 'systemctl %s\\n' "$*" >> '{trace}'
if [ "$1" = is-active ]; then [ -f '{active}' ] && exit 0 || exit 3; fi
if [ "$1" = stop ] && [ "$2" = xcli-core.service ]; then rm -f '{active}'; fi
if [ "$1" = start ] && [ "$2" = xcli-core.service ]; then touch '{active}'; fi
exit 0
''')
            nginx=root/'nginx';nginx.write_text(f"#!/bin/sh\nprintf 'nginx %s\\n' \"$*\" >> '{trace}'\nexit 0\n")
            checkpoint=root/'checkpoint'
            checkpoint.write_text(f'''#!/bin/sh
[ "$(id -u)" = '{UID}' ] || exit 2
printf 'checkpoint\\n' >> '{trace}'
[ -f '{failure}' ] && exit 1 || exit 0
''')
            for executable in (systemctl,nginx,checkpoint):executable.chmod(0o755)
            (root/'settings.json').write_text(json.dumps({'hysteria2_port':0,
                'residential_exits':[{'tag':'residential-01'}]}))
            monitor=root/'monitor';monitor.mkdir(mode=0o700)
            now=int(time.time());checks=[{'transport':tag,'status':'healthy','https_ms':5,'udp_ms':5,'error':'',
                'last_success':now} for tag in ('reality','websocket')]
            checks.append({'transport':'residential-01','status':'failed','https_ms':None,'doh_ms':None,
                'last_success':now-60,'error':'HTTPS connection failed'})
            report=monitor/'report.json';report.write_text(json.dumps({'schema':1,'scope':'server','status':'failed',
                'updated':now+2,'checks':checks}));report.chmod(0o640)
            class Ready(http.server.BaseHTTPRequestHandler):
                protocol_version='HTTP/1.1'
                def log_message(self,*_): pass
                def do_GET(self):
                    self.send_response(200 if self.path=='/internal/ready' else 404)
                    self.send_header('Content-Length','0');self.send_header('Connection','close');self.end_headers()
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Ready)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                args=[BINARY,'switch',str(root),str(UID),str(GID),str(server.server_port)]
                completed=subprocess.run(args,capture_output=True,timeout=20)
                self.assertEqual(completed.returncode,0,'an unrelated failed residential exit blocked the switch')
                self.assertEqual(trace.read_text().splitlines(),[
                    'systemctl stop xcli-monitor.service xcli-panel.service',
                    'systemctl is-active --quiet xcli-core.service', 'checkpoint',
                    'systemctl stop xcli-core.service','systemctl start xcli-core.service',
                    'systemctl start xcli-panel.service','nginx -t','systemctl reload nginx.service',
                    'systemctl start xcli-monitor.service'])
                self.assertTrue(active.exists())
                trace.write_text('');trace.chmod(0o666);failure.touch()
                failed=subprocess.run([BINARY,'stop',str(root),str(UID),str(GID),str(server.server_port)],
                    capture_output=True,timeout=20)
                self.assertNotEqual(failed.returncode,0)
                self.assertEqual(trace.read_text().splitlines(),[
                    'systemctl stop xcli-monitor.service xcli-panel.service',
                    'systemctl is-active --quiet xcli-core.service','checkpoint',
                    'systemctl start xcli-panel.service xcli-monitor.service'])
                self.assertTrue(active.exists(),'failed checkpoint stopped the core')
            finally:
                server.shutdown();server.server_close();thread.join(timeout=5)


if __name__ == '__main__':unittest.main()
