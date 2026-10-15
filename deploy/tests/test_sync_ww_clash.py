import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]/'scripts'))
try:
 import yaml
 import sync_ww_clash as s
except ImportError:
 s=None

@unittest.skipIf(s is None,'PyYAML is required for Clash profile editing')
class SyncTests(unittest.TestCase):
 def fixture(self,root):
  config=root/'config';(config/'profiles').mkdir(parents=True)
  (config/'profiles.yaml').write_text('current: selected\nitems:\n- uid: selected\n  option: {merge: m, rules: r}\n- {uid: m, file: m.yaml}\n- {uid: r, file: r.yaml}\n')
  (config/'profiles/m.yaml').write_text('dns:\n  nameserver-policy:\n    geosite:cn: [https://example.com/dns-query]\n  nameserver: [https://example.net/dns-query]\ncustom: retained\n')
  (config/'profiles/r.yaml').write_text('prepend:\n- DOMAIN,example.invalid,DIRECT\nappend: []\n')
  (config/'clash-verge.yaml').write_text('rules: [MATCH,PROXY]\ndns:\n  nameserver-policy: {geosite:cn: [https://example.com/dns-query]}\nproxies: []\n')
  policy={'suffixes':['corp.example.com'],'exact':[],'networks':['10.40.0.0/16'],'dns':{'corp.example.com':'127.0.0.1:10053'},'system_bypass':['*.corp.example.com']}
  return config,policy
 def test_priority_and_preserve_existing_settings(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);config,policy=self.fixture(root)
   with patch.object(s.local_network_policy,'load',return_value=policy):s.prepare(config,root/'out',root/'zprofile')
   data=yaml.safe_load((root/'out/merge.yaml').read_text())
   self.assertEqual(next(iter(data['dns']['nameserver-policy'])),'+.corp.example.com')
   self.assertTrue(data['dns']['direct-nameserver-follow-policy'])
   self.assertEqual(data['custom'],'retained')
   self.assertEqual(data['dns']['nameserver'],['https://example.net/dns-query'])
   rules=yaml.safe_load((root/'out/rules.yaml').read_text())['prepend']
   self.assertEqual(rules[0],'DOMAIN-SUFFIX,corp.example.com,DIRECT')
   self.assertIn('DOMAIN,example.invalid,DIRECT',rules)
 def test_apply_refuses_concurrent_changes(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);config,policy=self.fixture(root)
   with patch.object(s.local_network_policy,'load',return_value=policy):s.prepare(config,root/'out',root/'zprofile')
   original=(config/'profiles/r.yaml').read_bytes();(config/'profiles/m.yaml').write_text('user-change: true\n')
   with self.assertRaises(ValueError):s.apply(root/'out')
   self.assertEqual((config/'profiles/r.yaml').read_bytes(),original)
if __name__=='__main__':unittest.main()
