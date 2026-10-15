#!/usr/bin/env python3
"""Manually collect local logs, analyze on Oracle, and retrieve review-only reports."""
import argparse
import datetime
import os
import pathlib
import shlex
import subprocess
import tempfile
import routing_audit
import local_network_policy
import json

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_LOGS = pathlib.Path.home()/'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/logs'

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logs',type=pathlib.Path,default=DEFAULT_LOGS)
    parser.add_argument('--output',type=pathlib.Path,default=ROOT/'private/routing-audit')
    parser.add_argument('--ssh-alias',default='oracle')
    parser.add_argument('--host',default='161.153.70.208')
    parser.add_argument('--known-hosts',type=pathlib.Path,default=ROOT/'private/routing-audit/oracle-known-hosts')
    parser.add_argument('--zprofile',type=pathlib.Path,default=pathlib.Path.home()/'.zprofile')
    parser.add_argument('--max-ips',type=int,default=160)
    args=parser.parse_args()
    if not 1 <= args.max_ips <= 500:parser.error('max-ips must be between 1 and 500')
    if not args.known_hosts.is_file():parser.error('Provide a previously verified SSH known_hosts file')
    args.output.mkdir(parents=True,exist_ok=True,mode=0o700)
    options=['-o','BatchMode=yes','-o','ConnectTimeout=15','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2',
             '-o','ProxyCommand=none','-o','StrictHostKeyChecking=yes','-o','HostName='+args.host,'-o','UserKnownHostsFile='+str(args.known_hosts)]
    def ssh(command,**kwargs):
        return subprocess.run(['ssh',*options,args.ssh_alias,command],check=True,**kwargs)
    remote=None
    try:
        with tempfile.TemporaryDirectory(prefix='routing-audit-') as temporary:
            snapshot=pathlib.Path(temporary)/'observations.json'
            policy=local_network_policy.load(args.zprofile)
            value=routing_audit.collect(args.logs,policy)
            local_rows=value.pop('local_observations')
            local_report={'policy_source_sha256':policy['source_sha256'],'observations':local_rows,'uploaded':False,
                          'proxy_events':sum(r['count'] for r in local_rows if r['action']=='PROXY')}
            routing_audit.atomic(args.output/'local-policy-report.json',json.dumps(local_report,ensure_ascii=False,indent=2))
            assert all(not local_network_policy.match(r['host'],policy) for r in value['observations'])
            if not value['coverage']['events']:raise SystemExit('No routing events found; no upload performed')
            routing_audit.atomic(snapshot,__import__('json').dumps(value,ensure_ascii=False))
            print('Collected routing events:',value['coverage']['events'],flush=True)
            remote=ssh('umask 077; mktemp -d /var/tmp/xcli-routing-audit.XXXXXXXX',capture_output=True,text=True).stdout.strip()
            if not __import__('re').fullmatch(r'/var/tmp/xcli-routing-audit\.[A-Za-z0-9]{8}',remote):
                remote=None;raise RuntimeError('Invalid remote staging directory')
            subprocess.run(['scp',*options,str(ROOT/'scripts/routing_audit.py'),str(snapshot),args.ssh_alias+':'+remote+'/'],check=True)
            # One lock covers analysis, cache updates, and copying results to this unique run.
            code='''import fcntl,pathlib,runpy,shutil,sys
stage=pathlib.Path(sys.argv[1]);state=pathlib.Path.home()/'.local/state/xcli-routing-audit'
state.mkdir(parents=True,exist_ok=True,mode=0o700)
with (state/'run.lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 tool=runpy.run_path(str(stage/'routing_audit.py'))
 tool['analyze'](stage/'observations.json',state,max_ips=int(sys.argv[2]))
 for name in ('report.md','report.json','proposal.json','summary.json'):
  shutil.copyfile(state/name,stage/name)
'''
            command='python3 - '+shlex.quote(remote)+' '+str(args.max_ips)
            ssh(command,input=code,text=True,timeout=1200)
            for name in ('report.md','report.json','proposal.json','summary.json'):
                subprocess.run(['scp',*options,args.ssh_alias+':'+remote+'/'+name,str(args.output/name)],check=True)
            local_text='\n## 本机明确直连策略（未上传 Oracle）\n\n| 目标 | 命中依据 | 日志动作 | 事件数 |\n|---|---|---|---:|\n'
            for row in local_rows:
                local_text+='| '+row['host']+' | '+row['reason']+' | '+row['action']+' | '+str(row['count'])+' |\n'
            local_text+='\nPROXY 事件表示日志中曾违反本机策略，需结合记录时间判断是否发生在修复前。内网可达性应在本机验证。\n'
            with (args.output/'report.md').open('a') as report:report.write(local_text)
            # Preserve reviewed outputs locally without committing browsing observations to Git.
            archive=args.output/'history'/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
            archive.mkdir(parents=True,mode=0o700)
            for name in ('report.md','report.json','proposal.json','summary.json','local-policy-report.json'):
                __import__('shutil').copyfile(args.output/name,archive/name)
            print('Report: '+str(args.output/'report.md'))
            print('Review only: no subscription, DNS or routing configuration changed.')
    finally:
        if remote:
            try:ssh('rm -rf -- '+shlex.quote(remote),capture_output=True,timeout=20)
            except subprocess.SubprocessError:print('Remote staging cleanup failed; inspect '+remote)

if __name__=='__main__':main()
