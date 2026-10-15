import importlib.util
import json
import pathlib
import tempfile
import sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]/"scripts"))
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('routing_audit', pathlib.Path(__file__).resolve().parents[2]/'scripts/routing_audit.py')
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class AuditTests(unittest.TestCase):
    def test_collect_redacts_source_labels_urls_and_private_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            logs=pathlib.Path(directory)/'sidecar';logs.mkdir()
            lines=[
                'time="2026-10-15T10:00:00.123456789+08:00" msg="[TCP] 127.0.0.1:1234 --> docs.qq.com:443 match GeoSite(cn) using DIRECT"',
                'time="2026-10-15T10:01:00+08:00" msg="[TCP] 127.0.0.1:1234 --> other.example.com:443 match Match using PROXY[secret-user]"',
                'msg="[TCP] 127.0.0.1:1234 --> 192.168.1.1:443 match Match using DIRECT"',
                'msg="download https://example.com/s/SECRET_TOKEN"',
                'msg="[TCP] 127.0.0.1:1234 --> invalid.example.com/path?token=SECRET:443 match Match using PROXY"']
            (logs/'a.log').write_text('\n'.join(lines))
            value=m.collect(directory,policy={});encoded=json.dumps(value)
            self.assertEqual(value['coverage']['events'],2)
            self.assertEqual(value['coverage']['first'],'2026-10-15T02:00:00+00:00')
            for secret in ('127.0.0.1','192.168.1.1','SECRET','secret-user'):
                self.assertNotIn(secret,encoded)
    def test_suffix_boundary_and_exact(self):
        rules=({'exact.example.com'},{'qq.com'})
        self.assertEqual(m.rule_match('docs.qq.com',rules),'qq.com')
        self.assertIsNone(m.rule_match('notqq.com',rules))
        self.assertIsNone(m.rule_match('x.exact.example.com',rules))
    def test_geo_alone_never_generates_rule(self):
        row=m.classify({'host':'unknown.example.com','actions':{'PROXY':1}}, {}, {}, [{'status':'ok','country':'CN'}])
        self.assertEqual(row['state'],'review_ownership')
    def test_conflicts_and_already_direct(self):
        sets={k:(set(),{'qq.com'}) for k in ('direct','proxy','gfw')}
        row={'host':'docs.qq.com','actions':{'PROXY':1}}
        self.assertEqual(m.classify(row,sets,{},[])['state'],'conflict')
        row['actions']={'DIRECT':2}
        self.assertEqual(m.classify(row,sets,{},[])['state'],'already_direct')
    def test_offline_report_and_no_configuration_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);snapshot=root/'snapshot.json'
            snapshot.write_text(json.dumps({'schema':1,'coverage':{},'observations':[{'host':'docs.qq.com','action':'PROXY','count':3,'rule':'Match'}]}))
            sets={'direct':(set(),{'qq.com'}),'proxy':(set(),set()),'gfw':(set(),set())}
            with patch.object(m,'load_rules',return_value=(sets,{'status':'ok','revision':'a'*40})),patch.object(m,'resolve',return_value={'mock':{'addresses':[]}}):
                m.analyze(snapshot,root/'report')
                m.analyze(snapshot,root/'report')
            report=json.loads((root/'report/report.json').read_text())
            self.assertFalse(report['config_modified'])
            self.assertEqual(report['proposal']['rules'],['DOMAIN,docs.qq.com,DIRECT'])
            self.assertEqual(report['proposal']['status'],'awaiting_user_approval')
            self.assertFalse(json.loads((root/'report/summary.json').read_text())['meaningful_change'])
    def test_reject_injected_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot=pathlib.Path(directory)/'snapshot.json'
            snapshot.write_text(json.dumps({'schema':1,'observations':[{'host':'a.example.com\nMATCH,DIRECT','action':'PROXY','count':1,'rule':'Match'}]}))
            with self.assertRaises(ValueError):m.analyze(snapshot,pathlib.Path(directory)/'out')

if __name__=='__main__':unittest.main()
