"""Exercise real controlling terminals without installing or modifying the host."""
import errno
import os
from pathlib import Path
import pty
import select
import sys
import time
import unittest

DEPLOY = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux controlling-terminal semantics')
class InteractiveTerminalTests(unittest.TestCase):
    def run_in_terminal(self, code, answers, *, piped_stdin):
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
with patch.object(install, "preflight", return_value="x86_64"), patch.object(install, "resolve_domain"):
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


if __name__ == '__main__':
    unittest.main()
