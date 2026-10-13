#!/usr/bin/env python3
"""Bounded live node benchmark. Credentials stay in a private temporary directory."""
import argparse, concurrent.futures, contextlib, datetime, json, os, pathlib, socket
import math, statistics, subprocess, tempfile, time
from urllib.parse import parse_qs, urlsplit

p = argparse.ArgumentParser()
p.add_argument('--xray', required=True)
p.add_argument('--output', required=True)
p.add_argument('--stability-count', type=int, default=31)
p.add_argument('--control-url', default='')
args = p.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
links = json.loads((root/'private/client-links.json').read_text())
out = pathlib.Path(args.output); out.mkdir(parents=True, exist_ok=True)
records = []

def emit(record):
    record['at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    records.append(record)
    with (out/'client.jsonl').open('a') as f: f.write(json.dumps(record)+'\n')
    print(json.dumps(record), flush=True)

def request(kind, url, seconds=15, upload=None):
    cmd = ['curl','-sS','-f','--noproxy','*' if kind=='direct' else '',
           '--connect-timeout','10','--max-time',str(seconds),'-o','/dev/null',
           '-w','%{json}']
    if kind != 'direct': cmd += ['--proxy', proxies[kind]]
    if upload: cmd += ['--data-binary','@'+str(upload),'-H','Content-Type: application/octet-stream','-H','Expect:']
    result = subprocess.run(cmd+[url], capture_output=True, text=True, timeout=seconds+5)
    try: data=json.loads(result.stdout)
    except ValueError: data={}
    keep = ('http_code','time_connect','time_appconnect','time_starttransfer','time_total',
            'size_download','size_upload','speed_download','speed_upload','num_connects','remote_ip')
    data = {k:data.get(k) for k in keep}
    data.update(kind=kind, exit=result.returncode, error=result.stderr.strip()[:160])
    return data

def persistent(kind):
    cmd=['curl','-sS','-f','--no-buffer','--noproxy','','--proxy',proxies[kind],
         '--connect-timeout','10','--max-time','12','--rate','6/m','-w','%{json}\n']
    for i in range(args.stability_count):
        cmd += ['-o','/dev/null','https://www.cloudflare.com/cdn-cgi/trace']
    r=subprocess.run(cmd, capture_output=True, text=True, timeout=args.stability_count*11+30)
    rows=[]
    for line in r.stdout.splitlines():
        d=json.loads(line)
        rows.append({k:d.get(k) for k in ('http_code','exitcode','time_total','time_starttransfer','num_connects','errormsg')})
    (out/(kind+'-persistent.json')).write_text(json.dumps(rows,indent=2))
    good=[d for d in rows if d['http_code']==200 and d['exitcode']==0]
    warm=[d['time_total'] for d in good if d['num_connects']==0]
    return {'phase':'persistent','kind':kind,'requests':len(rows),'success':len(good),
            'connections':sum(d['num_connects'] for d in rows),
            'warm_median_s':statistics.median(warm) if warm else None,
            'warm_p95_s':sorted(warm)[math.ceil(len(warm)*.95)-1] if warm else None,
            'max_s':max(d['time_total'] for d in rows),'curl_exit':r.returncode}

proxies={}; processes=[]
with tempfile.TemporaryDirectory(prefix='xg-benchmark-') as directory:
    work=pathlib.Path(directory); work.chmod(0o700)
    upload=work/'upload.bin'; upload.write_bytes(os.urandom(4*1024*1024)); upload.chmod(0o600)
    try:
        for i,kind in enumerate(('reality','websocket')):
            uri=urlsplit(links[kind]); q={k:v[0] for k,v in parse_qs(uri.query).items()}
            stream={'network':q['type'],'security':q['security']}
            if kind=='reality':
                stream['realitySettings']={'serverName':q['sni'],'fingerprint':q['fp'],'publicKey':q['pbk'],'shortId':q['sid']}
            else:
                stream['tlsSettings']={'serverName':q['sni']}
                stream['wsSettings']={'path':q['path'],'headers':{'Host':q['host']}}
            user={'id':uri.username,'encryption':'none'}
            if 'flow' in q:user['flow']=q['flow']
            port=19081+i
            cfg={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':True}}],
                 'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':uri.hostname,'port':uri.port,'users':[user]}]},'streamSettings':stream}]}
            path=work/(kind+'.json');path.write_text(json.dumps(cfg));path.chmod(0o600)
            log=(work/(kind+'.log')).open('wb')
            process=subprocess.Popen([args.xray,'run','-config',str(path)],stdout=log,stderr=log)
            processes.append((process,log));proxies[kind]='socks5h://127.0.0.1:'+str(port)
        time.sleep(1)
        emit({'phase':'start','client':'Mac direct to 203.0.113.2','stability_minutes':(args.stability_count-1)/6})
        tcp=[]
        for i in range(12):
            start=time.monotonic()
            try:
                with socket.create_connection(('203.0.113.2',443),timeout=8):pass
                tcp.append(time.monotonic()-start)
            except OSError:tcp.append(None)
            time.sleep(.2)
        emit({'phase':'tcp443','samples_s':tcp})
        for i in range(10):
            for kind in (('reality','websocket') if i%2==0 else ('websocket','reality')):
                d=request(kind,'https://www.cloudflare.com/cdn-cgi/trace',seconds=12)
                emit(dict(d,phase='fresh_https',round=i+1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            pending={pool.submit(persistent,k):k for k in proxies}
            while pending:
                done,_=concurrent.futures.wait(pending,timeout=30,return_when=concurrent.futures.FIRST_COMPLETED)
                if not done:print('Persistent connections are under observation.',flush=True)
                for future in done:emit(future.result());del pending[future]
        for i in range(3):
            for kind in (('reality','websocket') if i%2==0 else ('websocket','reality')):
                d=request(kind,'https://speed.cloudflare.com/__down?bytes=52428800',seconds=15)
                d['mbps']=(d['size_download'] or 0)*8/max(d['time_total'] or 0,.001)/1e6
                d['bounded_sample']=d['exit']==28 and d['http_code']==200 and (d['size_download'] or 0)>0
                emit(dict(d,phase='download',round=i+1))
                d=request(kind,'https://speed.cloudflare.com/__up',seconds=25,upload=upload)
                d['mbps']=(d['size_upload'] or 0)*8/max(d['time_total'] or 0,.001)/1e6
                emit(dict(d,phase='upload',round=i+1))
        for kind in proxies:
            start=time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                rows=list(pool.map(lambda _:request(kind,'https://speed.cloudflare.com/__down?bytes=52428800',seconds=15),range(4)))
            elapsed=time.monotonic()-start
            emit({'phase':'parallel_download','kind':kind,'seconds':elapsed,'connections':4,
                  'mbps':sum(r['size_download'] or 0 for r in rows)*8/elapsed/1e6,'samples':rows})
        if args.control_url:
            for i in range(3):
                d=request('direct',args.control_url,seconds=15)
                d['mbps']=(d['size_download'] or 0)*8/max(d['time_total'] or 0,.001)/1e6
                emit(dict(d,phase='direct_https_control',round=i+1))
        emit({'phase':'complete'})
    finally:
        for process,log in processes:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):process.wait(timeout=5)
            if process.poll() is None:process.kill();process.wait()
            log.close()
