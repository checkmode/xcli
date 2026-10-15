import pathlib
import sys
import tempfile
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]/'scripts'))
import local_network_policy as p
import routing_audit as a

SOURCE='''function ww() {
 local_ip_list=(
  10.40.0.0/16
 )
 dns_routing_domains=(
  "corp.example.com"
 )
 proxy_bypass_domains=(
  '*.corp.example.com'
  localhost
  '*.local'
  192.168.0.0/16
 )
}
'''
class PolicyTests(unittest.TestCase):
 def fixture(self,root):
  profile=root/'zprofile';profile.write_text(SOURCE)
  resolvers=root/'resolver';resolvers.mkdir();(resolvers/'corp.example.com').write_text('nameserver 127.0.0.1\nport 10053\n')
  return profile,resolvers
 def test_load_dns_and_missing_bypass_added(self):
  with tempfile.TemporaryDirectory() as d:
   profile,resolvers=self.fixture(pathlib.Path(d));policy=p.load(profile,resolvers)
   self.assertEqual(policy['dns']['corp.example.com'],'127.0.0.1:10053')
   self.assertIn('corp.example.com',policy['system_bypass'])
   self.assertTrue(p.match('oa.corp.example.com',policy))
   self.assertFalse(p.match('notcorp.example.com',policy))
   self.assertTrue(p.match('10.40.2.3',policy))
 def test_empty_arrays_allow_removing_last_entry(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);profile,resolvers=self.fixture(root)
   profile.write_text("function ww() {\n local_ip_list=(\n )\n dns_routing_domains=(\n )\n proxy_bypass_domains=(\n )\n}\n")
   policy=p.load(profile,resolvers)
   self.assertEqual(p.rules(policy),[])
   self.assertEqual(policy['dns'],{})
   self.assertEqual(policy['system_bypass'],[])
 def test_dynamic_shell_is_rejected_without_execution(self):
  with tempfile.TemporaryDirectory() as d:
   profile,resolvers=self.fixture(pathlib.Path(d));profile.write_text(SOURCE.replace('10.40.0.0/16','$(touch /tmp/should-not-run)'))
   with self.assertRaises(ValueError):p.load(profile,resolvers)
 def test_local_observations_never_in_public_payload(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);profile,resolvers=self.fixture(root);policy=p.load(profile,resolvers)
   logs=root/'logs/sidecar';logs.mkdir(parents=True)
   (logs/'a.log').write_text('\n'.join('time="2026-10-15T10:00:00+08:00" msg="[TCP] 127.0.0.1:1 --> '+h+':443 match Match using PROXY"' for h in ['oa.corp.example.com','10.40.2.3','printer.local','localhost','www.google.com']))
   value=a.collect(root/'logs',policy)
   self.assertEqual([r['host'] for r in value['observations']],['www.google.com'])
   self.assertEqual(len(value['local_observations']),4)
   self.assertTrue(all(r['action']=='PROXY' for r in value['local_observations']))
 def test_missing_resolver_fails_closed(self):
  with tempfile.TemporaryDirectory() as d:
   profile,resolvers=self.fixture(pathlib.Path(d));(resolvers/'corp.example.com').unlink()
   with self.assertRaises(FileNotFoundError):p.load(profile,resolvers)
if __name__=='__main__':unittest.main()
