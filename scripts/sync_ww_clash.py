#!/usr/bin/env python3
"""Prepare/apply local profile extensions from ww. Never edit remote subscriptions."""
import argparse
import copy
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import yaml
import local_network_policy

ROOT=pathlib.Path(__file__).resolve().parents[1]

def prepare(config_dir,output,zprofile):
    policy=local_network_policy.load(zprofile)
    profiles=yaml.safe_load((config_dir/'profiles.yaml').read_text())
    active=next(p for p in profiles['items'] if p['uid']==profiles['current'])
    files={x['uid']:x['file'] for x in profiles['items'] if x.get('file')}
    targets={k:config_dir/'profiles'/files[active['option'][k]] for k in ('merge','rules')}
    for target in targets.values():
        if target.parent.resolve()!=(config_dir/'profiles').resolve() or target.is_symlink():raise ValueError('Unexpected profile path')
    original={k:p.read_bytes() for k,p in targets.items()}
    merge=yaml.safe_load(original['merge']) or {};rules=yaml.safe_load(original['rules']) or {}
    dns=merge.setdefault('dns',{})
    dns['direct-nameserver-follow-policy']=True
    mapping={'+.'+domain:[server] for domain,server in policy['dns'].items()}
    mapping.update({k:v for k,v in dns.get('nameserver-policy',{}).items() if k not in mapping})
    dns['nameserver-policy']=mapping
    old_filter=dns.get('fake-ip-filter',[])
    if not isinstance(old_filter,list):raise ValueError('Unsupported fake-ip-filter')
    dns['fake-ip-filter']=list(dict.fromkeys(old_filter+['+.'+s for s in policy['suffixes']]))
    managed=local_network_policy.rules(policy)
    rules['prepend']=list(dict.fromkeys(managed+rules.get('prepend',[])))
    candidate=yaml.safe_load((config_dir/'clash-verge.yaml').read_text())
    candidate['rules']=list(dict.fromkeys(managed+candidate['rules']))
    candidate['dns']['direct-nameserver-follow-policy']=True
    candidate['dns']['nameserver-policy']={**mapping,**{k:v for k,v in candidate['dns'].get('nameserver-policy',{}).items() if k not in mapping}}
    candidate['dns']['fake-ip-filter']=list(dict.fromkeys(candidate['dns'].get('fake-ip-filter',[])+dns['fake-ip-filter']))
    output.mkdir(parents=True,exist_ok=True,mode=0o700)
    for name,value in [('merge.yaml',merge),('rules.yaml',rules),('candidate.yaml',candidate)]:
        p=output/name;p.write_text(yaml.safe_dump(value,allow_unicode=True,sort_keys=False));p.chmod(0o600)
    (output/'policy.json').write_text(json.dumps(policy,ensure_ascii=False,indent=2))
    (output/'bypass.txt').write_text(','.join(policy['system_bypass']))
    manifest={'targets':{k:str(v) for k,v in targets.items()},'sha256':{k:hashlib.sha256(v).hexdigest() for k,v in original.items()},'profile_uid':active['uid']}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2))
    return policy

def apply(output):
    manifest=json.loads((output/'manifest.json').read_text())
    for kind,target in manifest['targets'].items():
        if hashlib.sha256(pathlib.Path(target).read_bytes()).hexdigest()!=manifest['sha256'][kind]:raise ValueError('Profile changed since preparation')
    backup=output/('backup-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(mode=0o700)
    for kind,target in manifest['targets'].items():shutil.copy2(target,backup/pathlib.Path(target).name)
    for kind,target in manifest['targets'].items():
        path=pathlib.Path(target);temporary=path.with_suffix(path.suffix+'.ww-tmp')
        temporary.write_bytes((output/(kind+'.yaml')).read_bytes());temporary.chmod(path.stat().st_mode & 0o777)
        os.replace(temporary,path)
    print('Local profile extensions saved. Backup: '+str(backup))
    print('Reactivate the profile in Clash Verge; apply bypass.txt in System Proxy settings.')

if __name__=='__main__':
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config-dir',type=pathlib.Path,default=pathlib.Path.home()/'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev')
    p.add_argument('--output',type=pathlib.Path,default=ROOT/'private/ww-clash')
    p.add_argument('--zprofile',type=pathlib.Path,default=pathlib.Path.home()/'.zprofile')
    p.add_argument('--apply',action='store_true');a=p.parse_args()
    if a.apply:apply(a.output)
    else:
        policy=prepare(a.config_dir,a.output,a.zprofile)
        print(json.dumps({'suffixes':policy['suffixes'],'dns':policy['dns'],'rules':len(local_network_policy.rules(policy))},ensure_ascii=False))
