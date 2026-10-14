import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(SOURCE/'scripts'))
sys.path.insert(0,str(SOURCE/'deploy'))
import proxy_vmess as vm
import proxy_import as imp
import provision

UUID='07a7ec9f-df87-4dfe-bb75-79e728517953'


def link(**fields):
    return 'vmess://'+base64.b64encode(json.dumps({'v':'2','ps':'Fixture','add':'1.1.1.1','port':'443','id':UUID,'aid':'0','net':'ws',
        'type':'none','host':'example.com','path':'/ws','tls':'tls','sni':'example.com',**fields}).encode()).decode()


class VMessTests(unittest.TestCase):
    def setUp(self):
        settings=provision.settings_for('panel.example.com','8.8.8.8','example.com','PrivateKey: '+('a'*43)+'\nPassword: '+('b'*43))
        self.old={'settings':json.dumps(settings).encode(),'core':json.dumps(provision.core_config(settings)).encode(),
            'monitor':json.dumps(provision.monitor_config(settings)).encode(),
            'nginx':provision.render_nginx(SOURCE,settings,'/test/cert.pem','/test/key.pem').encode()}
        self.p=vm.parse_links(link())[0]
        self.row={'status':'verified','exit_ip':'8.8.4.4','country':'US','server_ip':'1.1.1.1'}

    def test_link_and_outbound_preserve_tls_transport_and_secret(self):
        p=vm.parse_links(link(add='proxy.example.com',alpn='h2,http/1.1',fp='chrome'))[0]
        out=vm.outbound(p,'1.1.1.1')
        self.assertEqual(out['settings']['vnext'][0]['address'],'1.1.1.1')
        self.assertEqual(out['settings']['vnext'][0]['users'][0]['id'],UUID)
        self.assertEqual(out['streamSettings']['wsSettings']['path'],'/ws')
        self.assertFalse(out['streamSettings']['tlsSettings']['allowInsecure'])
        self.assertEqual(out['streamSettings']['tlsSettings']['alpn'],['h2','http/1.1'])
        self.assertEqual(vm.parse_links(link().rstrip('=')),[self.p])
        self.assertEqual(vm.parse_links('vmess://'+link()[8:].replace('+','-').replace('/','_').rstrip('=')),[self.p])

    def test_tcp_and_grpc_transport_details(self):
        tcp=vm.parse_links(link(net='tcp',path='',host='',tls='',sni=''))[0]
        out=vm.outbound(tcp,'1.1.1.1');self.assertEqual(out['streamSettings'],{'network':'tcp','security':'none'})
        grpc=vm.parse_links(link(net='grpc',path='my-service',type='gun'))[0]
        out=vm.outbound(grpc,'1.1.1.1')
        self.assertEqual(out['streamSettings']['grpcSettings'],{'serviceName':'my-service','authority':'example.com'})
        self.assertEqual(out['streamSettings']['tlsSettings']['alpn'],['h2'])

    def test_reject_unsupported_or_dangerous_fields_instead_of_ignoring(self):
        bad=[{'aid':64},{'net':'kcp'},{'type':'http'},{'allowInsecure':True},{'id':'invalid'},
             {'port':'0'},{'port':True},{'add':'127.0.0.1'},{'add':'169.254.169.254'},{'add':'::1'},
             {'add':'localhost'},{'add':'proxy.local'},{'add':'1.1.1.1/path'},{'host':'example.com\r\nHeader: value'},
             {'path':'not-absolute'},{'scy':'invalid'},{'fp':'unknown'},{'extra':'ignored would be unsafe'},{'mode':'multi'},
             {'net':'tcp','path':'/ws'},{'tls':'none','sni':'example.com'},{'alpn':'not-alpn'}]
        for fields in bad:
            with self.subTest(fields=fields),self.assertRaises(vm.InvalidProxy):vm.parse_links(link(**fields))
        for value in ['','vless://example','vmess://not-json',link()+'\n'+link(),'\n'.join([link(port=1000+n) for n in range(21)])]:
            with self.assertRaises(vm.InvalidProxy):vm.parse_links(value)

    def test_public_dns_results_are_pinned_and_mixed_private_answers_rejected(self):
        with patch.object(vm.socket,'getaddrinfo',return_value=[(2,1,6,'',('1.1.1.1',0))]):
            self.assertEqual(vm.resolve_public('proxy.example.com'),'1.1.1.1')
        with patch.object(vm.socket,'getaddrinfo',return_value=[(2,1,6,'',('1.1.1.1',0)),(2,1,6,'',('127.0.0.1',0))]):
            with self.assertRaises(vm.InvalidProxy):vm.resolve_public('proxy.example.com')

    def test_import_edit_trash_restore_preserve_uuid_without_disclosure(self):
        new,entries=imp.configure(self.old,[self.p],'vmess','VMess',[self.row]);tag=entries[0]['tag']
        self.assertEqual(json.loads(new['core'])['outbounds'][-1]['protocol'],'vmess')
        self.assertNotIn(UUID,json.dumps(imp.inventory(new)))
        self.assertNotIn(UUID,(new['settings']+new['monitor']+new['locations']).decode())
        change={'operation':'edit','tag':tag,'changes':{'label':'Renamed','uuid':'','path':'/new'}}
        edited,_,_=imp.manage_config(new,change,self.row)
        target=imp.load_pool(edited)['proxies'][0];self.assertEqual(target['uuid'],UUID);self.assertEqual(target['path'],'/new')
        deleted,_,_=imp.manage_config(edited,{'operation':'delete','tag':tag})
        self.assertNotIn(UUID,deleted['core'].decode())
        restored,_,_=imp.manage_config(deleted,{'operation':'restore','tag':tag})
        self.assertFalse(imp.inventory(restored)[0]['enabled'])
        enabled,_,_=imp.manage_config(restored,{'operation':'enable','tag':tag},self.row)
        self.assertIn(UUID,enabled['core'].decode());self.assertEqual(imp.load_pool(enabled)['proxies'][0]['path'],'/new')
        with self.assertRaises(vm.InvalidProxy):imp.manage_config(new,{'operation':'edit','tag':tag,'changes':{'protocol':'http'}})

    def test_entry_enable_preserves_current_registry_and_adds_monitor(self):
        new,entries=imp.vmess_entry_config(self.old);settings=json.loads(new['settings']);core=json.loads(new['core'])
        self.assertEqual(settings['vmess_ws_path'],settings['ws_path']+'/vmess')
        self.assertEqual(entries,[{'tag':'vmess','port':10081}]);self.assertEqual(core['inbounds'][-1]['protocol'],'vmess')
        self.assertEqual(core['inbounds'][:-1],json.loads(self.old['core'])['inbounds'])
        self.assertEqual(core['outbounds'],json.loads(self.old['core'])['outbounds'])
        self.assertIn('vmess',imp.monitor_tags(new));self.assertIn(str(imp.FILES['locations']).encode(),new['nginx'])
        self.assertEqual(json.loads(new['monitor'])['uuid'],json.loads(self.old['monitor'])['uuid'])
        with self.assertRaises(vm.InvalidProxy):imp.vmess_entry_config(new)
        later,_=imp.configure(new,[self.p],'vmess','Upstream',[self.row])
        self.assertIn('vmess',imp.monitor_tags(later))
        self.assertEqual(later['nginx'],new['nginx'])


if __name__=='__main__':unittest.main()
