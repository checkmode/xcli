"""Read literal ww policy arrays without executing shell code or changing networking."""
import hashlib
import ipaddress
import pathlib
import re
import shlex

ARRAYS = ('local_ip_list', 'dns_routing_domains', 'proxy_bypass_domains')

def load(path=None, resolver_dir='/etc/resolver'):
    path=pathlib.Path(path or pathlib.Path.home()/'.zprofile')
    text=path.read_text()
    start=re.search(r'^function\s+ww\s*\(\)\s*\{',text,re.M)
    if not start:raise ValueError('ww function is missing; refusing to infer local policy')
    body=text[start.end():]
    end=re.search(r'^\}',body,re.M)
    if not end:raise ValueError('Cannot locate ww function boundary')
    body=body[:end.start()]
    arrays={}
    for key in ARRAYS:
        found=re.search(r'^\s*'+key+r'=\(\s*\n(.*?)^\s*\)',body,re.M|re.S)
        if not found:raise ValueError('Missing literal policy array: '+key)
        words=shlex.split(found[1],comments=True)
        if not words or any(re.search(r'[$`\n;{}()]',word) for word in words):
            raise ValueError('Dynamic shell expressions are not supported in '+key)
        arrays[key]=words
    networks=set();suffixes=set();exact=set()
    bypass=set(arrays['proxy_bypass_domains'])
    for value in arrays['local_ip_list']+arrays['proxy_bypass_domains']:
        try:
            networks.add(str(ipaddress.ip_network(value,strict=False)))
            continue
        except ValueError:pass
        if '/' in value:raise ValueError('Invalid network')
        domain=value.removeprefix('*.') if hasattr(value,'removeprefix') else value[2:] if value.startswith('*.') else value
        if not re.fullmatch(r'[a-zA-Z0-9.-]+',domain):raise ValueError('Invalid bypass host')
        if value.startswith('*.'):
            suffixes.add(domain.lower());bypass.add(domain.lower())
        else:exact.add(domain.lower())
    dns={}
    for domain in arrays['dns_routing_domains']:
        if not re.fullmatch(r'[a-zA-Z0-9.-]+',domain):raise ValueError('Invalid resolver domain')
        suffixes.add(domain.lower());bypass.update((domain,'*.'+domain))
        values={}
        for line in (pathlib.Path(resolver_dir)/domain).read_text().splitlines():
            parts=line.split('#',1)[0].split()
            if len(parts)==2:values[parts[0]]=parts[1]
        address=str(ipaddress.ip_address(values['nameserver']));port=int(values.get('port','53'))
        if not 1<=port<=65535:raise ValueError('Invalid resolver port')
        dns[domain]=('['+address+']' if ':' in address else address)+':'+str(port)
    bypass.update(arrays['local_ip_list'])
    return {'schema':1,'source_sha256':hashlib.sha256(text.encode()).hexdigest(),
            'suffixes':sorted(suffixes),'exact':sorted(exact),'networks':sorted(networks),
            'dns':dns,'system_bypass':sorted(bypass)}

def match(target,policy):
    target=target.lower().rstrip('.')
    try:
        address=ipaddress.ip_address(target)
        return next(('network:'+n for n in policy.get('networks',[]) if address in ipaddress.ip_network(n)),None)
    except ValueError:pass
    if target in policy.get('exact',[]):return 'exact:'+target
    return next(('suffix:'+s for s in policy.get('suffixes',[]) if target==s or target.endswith('.'+s)),None)

def rules(policy):
    return (['DOMAIN,'+h+',DIRECT' for h in policy['exact']]+
            ['DOMAIN-SUFFIX,'+h+',DIRECT' for h in policy['suffixes']]+
            [('IP-CIDR6,' if ':' in n else 'IP-CIDR,')+n+',DIRECT,no-resolve' for n in policy['networks']])
