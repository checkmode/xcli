"""A pre-existing host identity must not give builds access to runtime data."""
import grp
from pathlib import Path
import pwd
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_environment as build


class BuildIdentityTests(unittest.TestCase):
    def test_safe_builder_can_be_reused_without_account_changes(self):
        account = pwd.struct_passwd(('xcli-build', 'x', 998, 998, build.BUILD_COMMENT, '/nonexistent', '/usr/sbin/nologin'))
        group = grp.struct_group(('xcli-build', 'x', 998, []))
        run = Mock()
        with patch.object(pwd, 'getpwnam', return_value=account), patch.object(pwd, 'getpwall', return_value=[account]), \
             patch.object(grp, 'getgrnam', return_value=group), patch.object(grp, 'getgrall', return_value=[group]):
            self.assertEqual(build.ensure_build_user(run), 'xcli-build')
        run.assert_not_called()

    def test_privileged_or_shared_builder_is_rejected_without_modification(self):
        baseline = ('xcli-build', 'x', 998, 998, build.BUILD_COMMENT, '/nonexistent', '/usr/sbin/nologin')
        group = grp.struct_group(('xcli-build', 'x', 998, []))
        variants = ((0, 998, '/nonexistent', '/usr/sbin/nologin'),
                    (998, 0, '/nonexistent', '/usr/sbin/nologin'),
                    (998, 998, '/var/lib/xray-gateway', '/usr/sbin/nologin'),
                    (998, 998, '/nonexistent', '/bin/bash'))
        for uid, gid, home, shell in variants:
            account = pwd.struct_passwd((baseline[0], baseline[1], uid, gid, baseline[4], home, shell))
            run = Mock()
            with self.subTest(uid=uid, gid=gid, home=home, shell=shell), \
                 patch.object(pwd, 'getpwnam', return_value=account), patch.object(pwd, 'getpwall', return_value=[account]), \
                 patch.object(grp, 'getgrnam', return_value=group), patch.object(grp, 'getgrall', return_value=[group]), \
                 self.assertRaises(ValueError):
                build.ensure_build_user(run)
            run.assert_not_called()
        account = pwd.struct_passwd(baseline)
        for groups, accounts in (([group, grp.struct_group(('xgateway', 'x', 997, ['xcli-build']))], [account]),
                                 ([group], [account, pwd.struct_passwd(('xgateway', 'x', 998, 997, '', '/', '/bin/false'))])):
            run = Mock()
            with patch.object(pwd, 'getpwnam', return_value=account), patch.object(pwd, 'getpwall', return_value=accounts), \
                 patch.object(grp, 'getgrnam', return_value=group), patch.object(grp, 'getgrall', return_value=groups), \
                 self.assertRaises(ValueError):
                build.ensure_build_user(run)
            run.assert_not_called()

    def test_existing_unowned_group_is_not_adopted(self):
        run = Mock()
        with patch.object(pwd, 'getpwnam', side_effect=KeyError), \
             patch.object(grp, 'getgrnam', return_value=grp.struct_group(('xcli-build', 'x', 998, []))), \
             self.assertRaises(ValueError):
            build.ensure_build_user(run)
        run.assert_not_called()
