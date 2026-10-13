#!/usr/bin/env python3
"""Read-only sampler for a bounded benchmark; no packets or proxy payloads captured."""
import datetime,json,pathlib,subprocess,time,os,sys
limit=int(sys.argv[1]) if len(sys.argv)>1 else 720
started=time.monotonic();previous={}
def run(command):return subprocess.run(command,capture_output=True,text=True,timeout=5).stdout.strip()
while time.monotonic()-started<limit:
    now=time.monotonic();data={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'load':pathlib.Path('/proc/loadavg').read_text().split()[:3]}
    data['mem']={line.split(':')[0]:int(line.split()[1]) for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemAvailable:','MemTotal:'))}
    data['cpu']=[int(x) for x in pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
    processes=[]
    for name in ('xray-gateway-core','xray-gateway-panel','nginx'):
        pid=int(run(['systemctl','show',name,'-p','MainPID','--value']) or '0')
        if pid:
            stat=pathlib.Path('/proc/'+str(pid)+'/stat').read_text().split()
            processes.append({'name':name,'pid':pid,'ticks':int(stat[13])+int(stat[14]),'rss':int(stat[23])*os.sysconf('SC_PAGE_SIZE')})
    data['processes']=processes
    data['network']=run(['ip','-s','-j','link','show','enp0s6'])
    data['tcp443']=run(['ss','-tin','state','established','(', 'sport', '=', ':443', ')'])
    data['qdisc']=run(['tc','-s','qdisc','show','dev','enp0s6'])
    print(json.dumps(data),flush=True)
    time.sleep(max(0,5-(time.monotonic()-now)))
