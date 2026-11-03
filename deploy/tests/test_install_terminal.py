"""Exercise real controlling terminals without installing or modifying the host."""
import errno
import os
from pathlib import Path
import pty
import select
import sys
import tempfile
import time
import unittest

DEPLOY = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux controlling-terminal semantics')
class InteractiveTerminalTests(unittest.TestCase):
    def run_in_terminal(self, code, answers, *, piped_stdin):
        # These are simulated installations; a host's real certificate and
        # renewal hook must not influence the subprocess's preflight.
        code = '''from pathlib import Path
_exists, _is_symlink = Path.exists, Path.is_symlink
def _certificate_path(path):
    return str(path).startswith("/etc/letsencrypt/")
Path.exists = lambda path: False if _certificate_path(path) else _exists(path)
Path.is_symlink = lambda path: False if _certificate_path(path) else _is_symlink(path)
''' + code
        sys.stdout.flush()
        sys.stderr.flush()
        pid, master = pty.fork()
        if pid == 0:
            try:
                if piped_stdin:
                    # Like curl | bash: stdin is not the controlling terminal.
                    devnull = os.open(os.devnull, os.O_RDONLY)
                    os.dup2(devnull, 0)
                    os.close(devnull)
                os.execv(sys.executable, [sys.executable, '-u', '-c', code])
            finally:
                os._exit(127)
        output = bytearray()
        pending = list(answers)
        end = time.monotonic() + 15
        finished = False
        try:
            while time.monotonic() < end:
                readable, _, _ = select.select([master], [], [], .2)
                if readable:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            finished = True
                            break
                        raise
                    if not chunk:
                        finished = True
                        break
                    output.extend(chunk)
                    if pending and pending[0][0].encode() in output:
                        _, answer = pending.pop(0)
                        os.write(master, answer.encode() + b'\n')
            if not finished:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
                self.fail('interactive installer timed out: ' + output.decode(errors='replace'))
            _, status = os.waitpid(pid, 0)
        finally:
            os.close(master)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, output.decode(errors='replace'))
        self.assertFalse(pending, output.decode(errors='replace'))
        return output.decode(errors='replace')

    def test_check_prompts_in_real_terminal_even_when_stdin_is_piped(self):
        code = f'''import sys
from unittest.mock import patch
sys.path.insert(0, {str(DEPLOY)!r})
import install
with patch.object(install, "preflight", return_value="x86_64"), patch.object(install, "resolve_domain"), patch.object(install, "save_checked_answers"):
    raise SystemExit(install.main(["--check", "--public-ip", "8.8.4.4"]))
'''
        for piped in (False, True):
            with self.subTest(piped_stdin=piped):
                out = self.run_in_terminal(code, [('面板域名', 'panel.example.com')], piped_stdin=piped)
                self.assertIn('只检查模式结束', out)
                self.assertNotIn('账户邮箱', out)
                self.assertNotIn('服务条款', out)

    def test_empty_answer_uses_default(self):
        code = f'''import sys
sys.path.insert(0, {str(DEPLOY)!r})
import install
print("RESULT=" + install.ask("IP", "8.8.4.4"))
'''
        out = self.run_in_terminal(code, [('IP [8.8.4.4]', '')], piped_stdin=True)
        self.assertIn('RESULT=8.8.4.4', out)

    def test_interactive_install_accepts_empty_email_and_confirmation(self):
        code = f'''import sys
from unittest.mock import patch
sys.path.insert(0, {str(DEPLOY)!r})
import install
class SimulatedInstaller:
    def __init__(self, args, arch, resolvers): self.args = args
    def execute(self):
        print("SIMULATED_INSTALL no_email=" + str(self.args.no_email))
        return 0
with patch.object(install, "preflight", return_value="x86_64"), patch.object(install, "resolve_domain"), patch.object(install, "Installer", SimulatedInstaller):
    raise SystemExit(install.main(["--public-ip", "8.8.4.4", "--no-tune-network"]))
'''
        out = self.run_in_terminal(code, [
            ('面板域名', 'panel.example.com'),
            ('Let\'s Encrypt 账户邮箱', ''),
            ('中的服务条款', 'yes'),
            ('确认在这台全新服务器安装', 'yes'),
        ], piped_stdin=True)
        self.assertIn('SIMULATED_INSTALL no_email=True', out)

    def test_check_answers_are_offered_on_the_next_install(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'answers' / 'answers.json')
            common = f'''import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, {str(DEPLOY)!r})
import install, install_cache
install_cache.CACHE_PATH = Path({path!r})
'''
            check = common + '''with patch.object(install, "preflight", return_value="x86_64"), patch.object(install, "resolve_domain"), patch.object(install.subprocess, "check_output", side_effect=OSError("offline")):
    raise SystemExit(install.main(["--check", "--email", "operator@example.com", "--reality-sni", "www.example.net"]))
'''
            out = self.run_in_terminal(check, [('面板域名', 'panel.example.com'), ('本机公网 IPv4', '8.8.4.4')], piped_stdin=True)
            self.assertIn('安装输入已保存', out)
            install_code = common + '''class SimulatedInstaller:
    def __init__(self, args, arch, resolvers): self.args = args
    def execute(self):
        print("CACHED_RESULT", self.args.domain, self.args.public_ip, self.args.email, self.args.reality_sni)
        return 0
with patch.object(install, "preflight", return_value="x86_64"), patch.object(install, "resolve_domain"), patch.object(install, "Installer", SimulatedInstaller):
    raise SystemExit(install.main([]))
'''
            out = self.run_in_terminal(install_code, [
                ('面板域名 [panel.example.com]', ''),
                ('本机公网 IPv4 [8.8.4.4]', ''),
                ("operator@example.com]", ''),
                ('中的服务条款', 'yes'),
                ('确认在这台全新服务器安装', 'yes'),
            ], piped_stdin=True)
            self.assertIn('CACHED_RESULT panel.example.com 8.8.4.4 operator@example.com www.example.net', out)

    def test_shell_reuses_checked_role_at_the_real_terminal(self):
        sys.path.insert(0, str(DEPLOY))
        import install_cache
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root/'cache'/'answers.json'
            install_cache.save('node', {'domain': 'node.example.com'}, path=cache)
            shell = (DEPLOY.parent/'install.sh').read_text().replace(
                '/root/.cache/xcli-install/answers.json', str(cache))
            script = root/'install.sh'
            script.write_text(shell)
            binaries = root/'bin'; binaries.mkdir()
            fake_uname = binaries/'uname'; fake_uname.write_text('#!/bin/sh\necho unsupported-test-host\n'); fake_uname.chmod(0o755)
            code = f'''import os, subprocess
os.environ['PATH'] = {str(binaries)!r} + ':' + os.environ['PATH']
subprocess.run(['bash', {str(script)!r}, '--check'], check=False)
print('EXPECTED_TEST_STOP')
'''
            out = self.run_in_terminal(code, [('请选择 [2]', '')], piped_stdin=True)
            self.assertIn('EXPECTED_TEST_STOP', out)


if __name__ == '__main__':
    unittest.main()
