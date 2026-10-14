import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(SOURCE/'deploy'))
import provision
spec=importlib.util.spec_from_file_location('proxy_import',SOURCE/'scripts/proxy_import.py')
imp=importlib.util.module_from_spec(spec);spec.loader.exec_module(imp)


class ProxyImportTests(unittest.TestCase):
    def setUp(self):
        settings=provision.settings_for('panel.example.com','8.8.8.8','example.com','PrivateKey: '+('a'*43)+'\nPassword: '+('b'*43))
        self.old={'settings':json.dumps(settings).encode(),'core':json.dumps(provision.core_config(settings)).encode(),
            'monitor':json.dumps(provision.monitor_config(settings)).encode(),
            'nginx':provision.render_nginx(SOURCE,settings,'/test/cert.pem','/test/key.pem').encode()}
        self.proxies=[{'address':'1.1.1.1','port':12324,'username':'fixture-user','password':'secret-fixture'}]
        self.rows=[{'status':'verified','exit_ip':'1.1.1.1','country':'SG','address':'1.1.1.1','port':12324}]

    def test_append_preserves_dynamic_fixed_and_routes_without_public_secrets(self):
        first,entries=imp.configure(self.old,self.proxies,'socks','IPRoyal ISP',self.rows)
        core=json.loads(first['core']);settings=json.loads(first['settings'])
        self.assertEqual(entries[0]['tag'],'residential-27')
        self.assertEqual(entries[0]['port'],10450)
        self.assertEqual(core['inbounds'][:-1],json.loads(self.old['core'])['inbounds'])
        self.assertEqual(core['routing']['rules'][:-2],json.loads(self.old['core'])['routing']['rules'])
        self.assertEqual(core['routing']['rules'][-2]['network'],'udp')
        self.assertEqual(core['outbounds'][-1]['protocol'],'socks')
        self.assertEqual(core['inbounds'][-1]['listen'],'127.0.0.1')
        self.assertNotIn(b'secret-fixture',first['settings']+first['monitor']+first['nginx']+first['locations'])
        self.assertIn(b'secret-fixture',first['core'])
        settings['residential_exits'].append({'tag':'residential-11','dynamic':True,'country':'US'})
        first['settings']=json.dumps(settings).encode()
        self.proxies[0]['address']='8.8.4.4';self.rows[0]['exit_ip']='8.8.4.4'
        second,entries=imp.configure(first,self.proxies,'http','Other',self.rows)
        self.assertEqual(entries[0]['tag'],'residential-28')
        self.assertEqual(json.loads(second['settings'])['residential_exits'][:-1],settings['residential_exits'])
        self.assertEqual(json.loads(second['core'])['outbounds'][:-1],core['outbounds'])
        self.assertEqual(json.loads(second['core'])['outbounds'][-1]['protocol'],'http')
        self.assertEqual(second['nginx'],first['nginx'])
        self.assertEqual(len(json.loads(second['monitor'])['residential_exits']),2)

    def test_reject_private_multicast_and_control_characters(self):
        for ip in ('127.0.0.1','169.254.169.254','10.0.0.1','224.0.0.1','100.64.0.1','::1','example.com','1.1.1.01'):
            p=copy.deepcopy(self.proxies);p[0]['address']=ip
            with self.subTest(ip=ip),self.assertRaises(imp.ImportErrorSafe):imp.validate(p,'socks','label')
        for field in ('username','password'):
            p=copy.deepcopy(self.proxies);p[0][field]='secret\nurl = "file:///etc/shadow"'
            with self.assertRaises(imp.ImportErrorSafe):imp.validate(p,'socks','label')
        with self.assertRaises(imp.ImportErrorSafe):imp.validate(self.proxies,'freedom','label')
        with self.assertRaises(imp.ImportErrorSafe):imp.validate(self.proxies*2,'socks','label')

    def test_duplicate_capacity_unverified_and_catchall_rejected(self):
        first,_=imp.configure(self.old,self.proxies,'socks','label',self.rows)
        with self.assertRaises(imp.ImportErrorSafe):imp.configure(first,self.proxies,'socks','label',self.rows)
        self.rows[0]['status']='failed'
        with self.assertRaises(imp.ImportErrorSafe):imp.configure(self.old,self.proxies,'socks','label',self.rows)
        self.rows[0]['status']='verified'
        settings=json.loads(self.old['settings']);settings['residential_exits']=[{}]*40;self.old['settings']=json.dumps(settings).encode()
        with self.assertRaises(imp.ImportErrorSafe):imp.configure(self.old,self.proxies,'socks','label',self.rows)
        settings['residential_exits']=[];self.old['settings']=json.dumps(settings).encode()
        core=json.loads(self.old['core']);core['routing']['rules'].append({'type':'field','network':'tcp','outboundTag':'direct'});self.old['core']=json.dumps(core).encode()
        with self.assertRaises(imp.ImportErrorSafe):imp.configure(self.old,self.proxies,'socks','label',self.rows)

    def test_probe_credentials_only_stdin_and_failure_sanitized(self):
        owner=types.SimpleNamespace(pw_uid=123,pw_gid=456)
        good=subprocess.CompletedProcess([],0,b'ip=1.1.1.1\nloc=SG\n',b'')
        dns=subprocess.CompletedProcess([],0,b'\x04\xd2\x81\x80\x00\x01\x00\x01'+b'\0'*4,b'')
        with patch.object(imp.pwd,'getpwnam',return_value=owner),patch.object(imp.subprocess,'run',side_effect=[good,dns]) as run:
            row=imp.probe(self.proxies[0],'socks')
            self.assertEqual(row['status'],'verified')
            for call in run.call_args_list:
                self.assertNotIn('secret-fixture',str(call.args))
                self.assertIn(b'secret-fixture',call.kwargs['input'])
                self.assertEqual(call.kwargs['user'],123)
            self.assertNotIn('secret-fixture',json.dumps(row))
        bad=subprocess.CompletedProcess([],97,b'',b'secret-fixture')
        with patch.object(imp.pwd,'getpwnam',return_value=owner),patch.object(imp.subprocess,'run',return_value=bad):
            self.assertNotIn('secret-fixture',json.dumps(imp.probe(self.proxies[0],'http')))

    def test_symlink_and_oversized_requests_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'data';p.write_text('12345');link=Path(tmp)/'link';link.symlink_to(p)
            with self.assertRaises(OSError):imp.read_regular(link)
            with self.assertRaises(imp.ImportErrorSafe):imp.read_regular(p,4)

    def test_encrypted_request_context_and_tamper(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key=b'k'*32;nonce=b'n'*12;encrypted=AESGCM(key).encrypt(nonce,b'{"id":"test"}',imp.CONTEXT)
        blob=b'XGB1'+nonce+encrypted[-16:]+encrypted[:-16]
        self.assertEqual(imp.unseal(blob,key),{'id':'test'})
        with self.assertRaises(Exception):imp.unseal(blob[:-1]+bytes([blob[-1]^1]),key)

    def test_new_job_never_exposes_previous_terminal_state(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        for action in ('preview','apply'):
            with tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);inbox=directory/'request.xgb';key=b'k'*32;nonce=b'n'*12
                request={'id':'a'*32,'action':action,'requested_at':imp.stamp()}
                encrypted=AESGCM(key).encrypt(nonce,json.dumps(request).encode(),imp.CONTEXT)
                inbox.write_bytes(b'XGB1'+nonce+encrypted[-16:]+encrypted[:-16])
                worker=imp.Worker.__new__(imp.Worker);worker.key=key;worker.processed=[]
                with patch.object(imp,'ROOT',directory),patch.object(imp,'INBOX',inbox),patch.object(imp,'atomic'),patch.object(worker,'publish') as publish,patch.object(worker,'preview'),patch.object(worker,'apply'):
                    worker.process()
                    self.assertEqual(publish.call_args_list[0].kwargs['status'],'verifying' if action=='preview' else 'applying')
                    self.assertEqual(publish.call_args_list[0].kwargs['id'],request['id'])

    def test_rollback_keeps_original_pool_and_refuses_changed_config(self):
        new,_=imp.configure(self.old,self.proxies,'socks','label',self.rows)
        with tempfile.TemporaryDirectory() as tmp:
            backup=Path(tmp);manifest={'metadata':{k:[0o600,0,0] for k in self.old},'allowed':{k:[imp.hashlib.sha256(v).hexdigest()] for k,v in new.items()}}
            (backup/'manifest.json').write_text(json.dumps(manifest))
            for k,v in self.old.items():(backup/k).write_bytes(v)
            paths={k:backup/('live-'+k) for k in imp.FILES}
            for k,v in new.items():paths[k].write_bytes(v)
            def write(path,data,*args):path.write_bytes(data.encode() if isinstance(data,str) else data)
            with patch.object(imp,'FILES',paths),patch.object(imp,'atomic',side_effect=write),patch.object(imp,'run'),patch.object(imp,'service_start',return_value=123),patch.object(imp,'wait_ready'):
                imp.rollback(backup)
                for k,v in self.old.items():self.assertEqual(paths[k].read_bytes(),v)
                self.assertFalse(paths['locations'].exists());self.assertFalse(paths['pool'].exists())
            paths['settings'].write_text('{}')
            with patch.object(imp,'FILES',paths),self.assertRaises(imp.ImportErrorSafe):imp.rollback(backup)


if __name__=='__main__':unittest.main()
