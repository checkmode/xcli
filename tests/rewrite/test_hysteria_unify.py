"""Test migration of a single rate-controlled Hysteria listener."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('hy2_unify', ROOT / 'rewrite/deploy/unify-hysteria-brutal.py')
unify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(unify)


def fixture():
    settings = {'hysteria2_port':443, 'hysteria2_brutal_port':8443, 'hysteria2_brutal_mbps':60,
                'residential_exits':[{'tag':'residential-01','hysteria2':True}], 'other':'retained'}
    base = {'listen':'0.0.0.0', 'protocol':'hysteria', 'settings':{'version':2,'clients':[]},
            'streamSettings':{'network':'hysteria','security':'tls','finalmask':{'quicParams':{'congestion':'bbr'}}}}
    old = dict(copy.deepcopy(base),tag='hysteria2',port=443)
    new = dict(copy.deepcopy(base),tag='hysteria2-brutal',port=8443)
    new['streamSettings']['finalmask']['quicParams'] = {'congestion':'force-brutal','brutalUp':'60 mbps'}
    routes = [{'ruleTag':'residential-01-hy2-'+network,'inboundTag':['hysteria2'],
               'user':['regexp:@residential-01-hy2$'],'network':network,'outboundTag':target}
              for network,target in [('udp','blocked'),('tcp','residential-01-exit')]]
    core = {'inbounds':[old,new,{'tag':'websocket'}], 'outbounds':[{'tag':'residential-01-exit'}], 'routing':{'rules':routes}}
    monitor = {'hysteria2_port':443, 'hysteria2_brutal_port':8443, 'other':'retained'}
    return settings,core,monitor


def candidate(values):
    return unify.build_candidates(*(json.dumps(v).encode() for v in values))


class UnifiedHysteriaTests(unittest.TestCase):
    def test_preserves_routes_and_identity_while_replacing_listener(self):
        settings,core,monitor = fixture()
        result = candidate((settings,core,monitor))
        updated = {k:json.loads(v) for k,v in result.items()}
        self.assertEqual(updated['settings']['hysteria2_port'],8443)
        self.assertEqual(updated['settings']['hysteria2_brutal_port'],0)
        self.assertTrue(updated['settings']['hysteria2_primary_brutal'])
        self.assertEqual(updated['settings']['other'],'retained')
        self.assertEqual(updated['monitor']['hysteria2_port'],8443)
        self.assertEqual(updated['monitor']['hysteria2_brutal_port'],0)
        self.assertEqual(updated['core']['routing'],core['routing'])
        self.assertEqual(updated['core']['outbounds'],core['outbounds'])
        self.assertEqual([i['tag'] for i in updated['core']['inbounds']],['hysteria2','websocket'])
        self.assertEqual(updated['core']['inbounds'][0]['port'],8443)
        self.assertEqual(updated['core']['inbounds'][0]['streamSettings']['finalmask']['quicParams']['brutalUp'],'60 mbps')
        self.assertIsNone(candidate((updated['settings'],updated['core'],updated['monitor'])))

    def test_rejects_unsafe_or_inconsistent_input(self):
        for mutate in (
            lambda s,c,m: c['routing']['rules'][1].update(outboundTag='direct'),
            lambda s,c,m: c['routing']['rules'].append({'inboundTag':['hysteria2-brutal']}),
            lambda s,c,m: c['inbounds'][1]['settings']['clients'].append({'auth':'other'}),
            lambda s,c,m: c['inbounds'][1]['streamSettings']['finalmask']['quicParams'].update(brutalUp='40 mbps'),
            lambda s,c,m: m.update(hysteria2_brutal_port=443),
        ):
            data = fixture()
            mutate(*data)
            with self.assertRaises(ValueError): candidate(data)

    def test_failure_after_restart_restores_all_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = fixture()
            paths = {name: root / name for name in ('settings', 'core', 'monitor')}
            before, metadata = {}, {}
            for (name, path), value in zip(paths.items(), values):
                path.write_text(json.dumps(value))
                before[name], metadata[name] = unify.support.regular_bytes(path)
            after = candidate(values)
            info = {'db':root/'db', 'core_pid':root/'pid', 'port':18080}
            calls = []
            def run(*args, **kwargs):
                calls.append(args)
            with patch.object(unify.upgrade, 'BACKUPS', root/'backups'), \
                 patch.object(unify.upgrade, 'active', return_value=True), \
                 patch.object(unify.upgrade, 'core_generation', return_value='123'), \
                 patch.object(unify.upgrade, 'run', side_effect=run), \
                 patch.object(unify.upgrade, 'snapshot'), \
                 patch.object(unify.upgrade, 'private_rows', return_value=([], {})), \
                 patch.object(unify, 'checkpoint'), \
                 patch.object(unify, 'start_services'), \
                 patch.object(unify, 'wait_runtime_tags', side_effect=RuntimeError('injected failure')):
                with self.assertRaisesRegex(RuntimeError, 'injected failure'):
                    unify.apply(info, Path('/test/xray'), '127.0.0.1:10085', paths, before, metadata, after)
            for name, path in paths.items():
                self.assertEqual(path.read_bytes(), before[name])
            restarts = [call for call in calls if call == ('systemctl', 'restart', 'xray-gateway-core')]
            self.assertEqual(len(restarts), 2)

if __name__ == '__main__': unittest.main()
