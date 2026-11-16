#!/usr/bin/env python3
# Extracted verbatim from SweepNinja perform_classification()
import sys, json, os
from collections import defaultdict

data    = json.load(open(sys.argv[1]))
out_dir = sys.argv[2]
total   = len(data)

HTTP_SERVICES = {
    'http','https','http-alt','http-proxy','https-alt','ssl/http','ssl/https',
    'webcache','www','webmanager','apache','nginx','tomcat','jetty',
    'http-mgmt','http-rpc-epmap','soap','xmlrpc','node.js'
}
HTTP_PORTS = {
    80,443,8080,8443,8000,8008,8888,8181,8180,8009,9000,9080,9090,
    9443,3000,3001,4000,4443,5000,5001,6000,7000,7001,7080,7443,
    10080,10443,11080,11180,11187,11188,11442,11443,11444,12090,
    12095,28080,2381
}
HTTPS_SERVICES = {'https','ssl','ssl/http','ssl/https','https-alt','https-proxy','imaps','pop3s','smtps'}
HTTPS_PORTS    = {443,8443,4443,10443,11443,11444}

def is_http(e):
    svc  = e['service'].lower()
    port = int(e['port']) if e['port'].isdigit() else 0
    return svc in HTTP_SERVICES or port in HTTP_PORTS

def is_https(e):
    svc    = e['service'].lower()
    port   = int(e['port']) if e['port'].isdigit() else 0
    tunnel = e['tunnel'].lower()
    return tunnel == 'ssl' or svc in HTTPS_SERVICES or port in HTTPS_PORTS

# ── http.txt ──────────────────────────────────────────────────
http_lines = []
for e in data:
    if is_http(e):
        scheme = 'https' if is_https(e) else 'http'
        http_lines.append(f"{scheme}://{e['ip']}:{e['port']}")
http_lines = sorted(set(http_lines),
    key=lambda x: (x.split('://')[1].split(':')[0].split('.'), int(x.split(':')[-1])))
with open(os.path.join(out_dir, 'http.txt'), 'w') as f:
    f.write('\n'.join(http_lines) + '\n' if http_lines else '')
print(f"  HTTP         http.txt               {len(http_lines):>4} entries")

# ── per-service files ─────────────────────────────────────────
SERVICE_ALIASES = {
    'ssh':           ['ssh'],
    'ftp':           ['ftp'],
    'telnet':        ['telnet'],
    'smtp':          ['smtp','smtps','submission'],
    'dns':           ['dns','domain'],
    'http':          list(HTTP_SERVICES),
    'smb':           ['microsoft-ds','netbios-ssn','smb','cifs'],
    'rdp':           ['ms-wbt-server','rdp','remote-desktop'],
    'ldap':          ['ldap','ldaps'],
    'snmp':          ['snmp'],
    'nfs':           ['nfs','mountd','nlockmgr','rpcbind','rpc'],
    'mysql':         ['mysql'],
    'mssql':         ['ms-sql-s','ms-sql-m','mssql'],
    'postgresql':    ['postgresql'],
    'redis':         ['redis'],
    'mongodb':       ['mongodb'],
    'elasticsearch': ['elasticsearch'],
    'kibana':        ['kibana'],
    'kafka':         ['kafka'],
    'zookeeper':     ['zookeeper'],
    'imap':          ['imap','imaps'],
    'pop3':          ['pop3','pop3s'],
    'vnc':           ['vnc','vnc-http','rfb'],
    'printer':       ['ipp','jetdirect','printer','pdl-datastream'],
    'oracle':        ['oracle','oracle-tns'],
    'cassandra':     ['cassandra'],
    'memcached':     ['memcached'],
    'rsync':         ['rsync'],
    'tftp':          ['tftp'],
    'ntp':           ['ntp'],
    'kerberos':      ['kerberos','kpasswd'],
    'bgp':           ['bgp'],
    'docker':        ['docker'],
    'kubernetes':    ['kubernetes'],
    'etcd':          ['etcd'],
    'consul':        ['consul'],
    'prometheus':    ['prometheus'],
    'grafana':       ['grafana'],
    'influxdb':      ['influxdb'],
    'rabbitmq':      ['amqp','rabbitmq'],
    'mqtt':          ['mqtt'],
    'citrix':        ['citrix','ica'],
}
rev = {}
for key, names in SERVICE_ALIASES.items():
    for n in names:
        rev[n.lower()] = key

buckets = defaultdict(list)
for e in data:
    svc = e['service'].lower()
    key = rev.get(svc, svc if svc else None)
    if key and key != 'http':
        buckets[key].append(e)

svc_counts = {}
for key, entries in buckets.items():
    lines = sorted(
        {f"{e['ip']} Port {e['port']}" for e in entries},
        key=lambda x: (list(map(int, x.split()[0].split('.'))), int(x.split()[-1]))
    )
    with open(os.path.join(out_dir, f"{key}.txt"), 'w') as f:
        f.write('\n'.join(lines) + '\n')
    svc_counts[key] = len(lines)
    print(f"  {key.upper():<12} {key+'.txt':<22} {len(lines):>4} entries")

# ── vulnerability checklist ───────────────────────────────────
VULN_MAP = {
    'ftp':           ['Test anonymous FTP login (USER anonymous)',
                      'Check for FTP bounce attack',
                      'Banner grabbing — identify software version',
                      'Brute-force weak credentials',
                      'Test for cleartext credential sniffing (no TLS)'],
    'ssh':           ['Brute-force weak credentials (hydra/medusa)',
                      'Check for outdated SSH protocol version (SSHv1)',
                      'Test for weak host key algorithms (DSA 1024)',
                      'Username enumeration (timing-based)',
                      'Check for default/vendor credentials on appliances'],
    'telnet':        ['Capture cleartext credentials (wireshark/tcpdump)',
                      'Brute-force credentials',
                      'Banner grab for OS/version fingerprinting',
                      'Test for unauthenticated access'],
    'smtp':          ['Test for open relay (RCPT TO external domain)',
                      'VRFY/EXPN username enumeration',
                      'Banner grab for version',
                      'Check STARTTLS enforcement'],
    'smb':           ['Test for EternalBlue (MS17-010)',
                      'Check for null session / anonymous access (smbclient -N)',
                      'Enumerate shares (smbmap, crackmapexec)',
                      'Test for SMBv1 enabled',
                      'Brute-force credentials',
                      'Check for PrintNightmare (CVE-2021-1675)'],
    'rdp':           ['Test for BlueKeep (CVE-2019-0708)',
                      'Brute-force credentials (crowbar/ncrack)',
                      'Check NLA enforcement',
                      'Man-in-the-middle (missing NLA)',
                      'Check for DejaBlue (CVE-2019-1181/1182)'],
    'ldap':          ['Test for anonymous bind',
                      'Enumerate users/groups/OUs',
                      'Check for LDAP injection',
                      'Credential brute-force'],
    'snmp':          ['Test default community strings (public/private)',
                      'Enumerate via snmpwalk',
                      'Check for SNMPv1/v2 (cleartext)',
                      'Write access via community string'],
    'nfs':           ['List exports (showmount -e)',
                      'Mount without auth (no_root_squash)',
                      'Check world-readable/writable shares',
                      'Symlink attacks'],
    'mysql':         ['Test root with no password',
                      'Brute-force credentials',
                      'Check for UDF privilege escalation',
                      'SQL injection via exposed port'],
    'mssql':         ['Test SA account with blank/weak password',
                      'Enable xp_cmdshell for RCE',
                      'Check for linked servers',
                      'Brute-force credentials (Metasploit mssql_login)'],
    'postgresql':    ['Test postgres role with no password',
                      'Check pg_hba.conf trust entries',
                      'COPY TO/FROM PROGRAM for RCE',
                      'Brute-force credentials'],
    'redis':         ['Unauthenticated access (redis-cli ping)',
                      'CONFIG SET dir / dbfilename for RCE via SSH keys',
                      'Check for SLAVEOF replication abuse',
                      'Brute-force AUTH password'],
    'mongodb':       ['Test for authentication disabled',
                      'Enumerate databases without credentials',
                      'Check for NoSQL injection exposure',
                      'Network exposure (no TLS)'],
    'elasticsearch': ['Unauthenticated access to /_cat/indices',
                      'Data exfiltration via REST API',
                      'RCE via Groovy/MVEL script injection (old versions)',
                      'Check for X-Pack security disabled'],
    'kibana':        ['Unauthenticated dashboard access',
                      'Check for Kibana CVE-2019-7609 (Timelion RCE)',
                      'Prototype pollution vulnerabilities',
                      'Access to Elasticsearch through Kibana proxy'],
    'vnc':           ['Test for no-authentication mode',
                      'Brute-force VNC password (4-byte key)',
                      'Screen capture without auth',
                      'Check LibVNCServer CVE exposure'],
    'printer':       ['Access embedded web server (default creds)',
                      'IPP job submission without auth',
                      'PJL filesystem traversal',
                      'SNMP printer MIB enumeration',
                      'Capture print jobs (cleartext)'],
    'imap':          ['Brute-force credentials',
                      'Check STARTTLS enforcement',
                      'Banner grab for version',
                      'Test for cleartext transmission'],
    'pop3':          ['Brute-force credentials',
                      'Check for STLS enforcement',
                      'Clear text credential capture'],
    'dns':           ['Zone transfer (dig AXFR)',
                      'DNS cache poisoning',
                      'DNS amplification (open resolver)',
                      'Subdomain enumeration'],
    'docker':        ['Unauthenticated Docker API (RCE risk)',
                      'Container escape via mounted /var/run/docker.sock',
                      'Check for privileged containers',
                      'Registry access without auth'],
    'kubernetes':    ['Unauthenticated API server access',
                      'Enumerate secrets/pods/namespaces',
                      'RBAC misconfiguration',
                      'etcd unauthenticated access',
                      'Kubelet read-only port (10255)'],
    'consul':        ['Unauthenticated HTTP API',
                      'Service mesh misconfiguration',
                      'Key/Value store data exposure',
                      'ACL bypass'],
    'prometheus':    ['Unauthenticated metrics endpoint',
                      'Internal network topology disclosure',
                      'PromQL injection'],
    'grafana':       ['Default admin:admin credentials',
                      'Check CVE-2021-43798 (path traversal)',
                      'SSRF via datasource configuration',
                      'Snapshot authentication bypass'],
    'rabbitmq':      ['Default guest:guest credentials',
                      'Management UI unauthenticated access',
                      'Message queue poisoning',
                      'Shodan-exposed instances'],
    'rsync':         ['Unauthenticated module access',
                      'List modules (rsync --list-only)',
                      'File read/write without auth'],
    'oracle':        ['Default SID enumeration (tnscmd10g)',
                      'Brute-force credentials (oscanner)',
                      'TNS Listener poison attack',
                      'Check for default accounts (SCOTT/TIGER)'],
    'ntp':           ['NTP amplification/DRDoS',
                      'monlist query for reconnaissance',
                      'NTP mode 6/7 abuse'],
    'kerberos':      ['AS-REP Roasting (no pre-auth)',
                      'Kerberoasting (SPN enumeration)',
                      'Pass-the-ticket attacks',
                      'MS14-068 Kerberos PAC privilege escalation'],
    'mqtt':          ['Unauthenticated broker access',
                      'Subscribe to # wildcard topic',
                      'Brute-force credentials',
                      'Clear text credential capture'],
    'memcached':     ['Unauthenticated access',
                      'Memcached DRDoS amplification',
                      'Data exfiltration via stats command'],
    'citrix':        ['CVE-2019-19781 (Citrix ADC path traversal/RCE)',
                      'Brute-force credentials',
                      'Session token theft'],
    'http':          ['Directory/file brute-force (feroxbuster/gobuster)',
                      'Check for default credentials on admin panels',
                      'Test for SQLi, XSS, SSRF, XXE, IDOR',
                      'Check HTTP methods (PUT/DELETE/TRACE)',
                      'Missing security headers (CSP, HSTS, X-Frame)',
                      'Sensitive info in JS source / robots.txt / .git',
                      'Test for clickjacking',
                      'Check TLS configuration (sslscan/testssl.sh)'],
}

found_services = set(buckets.keys())
found_services.add('http')
lines = ['='*62, '  VULNERABILITY CHECKLIST  —  SweepNinja', '='*62]
for svc in sorted(found_services):
    checks = VULN_MAP.get(svc, ['Manual review recommended'])
    lines.append(f'\n[{svc.upper()}]')
    for c in checks:
        lines.append(f'  • {c}')
with open(os.path.join(out_dir, 'vulnerabilities_checklist.txt'), 'w') as f:
    f.write('\n'.join(lines) + '\n')
print(f"  VULN         vulnerabilities_checklist.txt  {len(found_services):>4} services")

# ── components.txt ────────────────────────────────────────────
comp_map = defaultdict(set)
for e in data:
    prod = e['product'].strip()
    ver  = e['version'].strip()
    if prod:
        comp_map[f"{prod} {ver}".strip()].add(e['ip'])

lines = ['='*62, '  COMPONENTS & VERSIONS  —  SweepNinja', '='*62]
for comp, ips in sorted(comp_map.items()):
    lines.append(f'\n  {comp}')
    lines.append(f"    IPs: {', '.join(sorted(ips, key=lambda x: list(map(int,x.split('.')))))}")
with open(os.path.join(out_dir, 'components.txt'), 'w') as f:
    f.write('\n'.join(lines) + '\n')
print(f"  COMPONENTS   components.txt         {len(comp_map):>4} components")

# ── cache for searchsploit ────────────────────────────────────
# Group by (product, version) — keep them separate as nmap reports them
# so searchsploit gets the most accurate query possible
ss_seen = {}  # (product, version) -> set of ips
for e in data:
    prod = e['product'].strip()
    ver  = e['version'].strip()
    if prod:
        key = (prod, ver)
        ss_seen.setdefault(key, set()).add(e['ip'])

ss_data = []
for (prod, ver), ips in sorted(ss_seen.items()):
    ss_data.append({'product': prod, 'version': ver, 'ips': sorted(ips)})
with open(os.path.join(out_dir, '.components_cache.json'), 'w') as f:
    json.dump(ss_data, f)

# ── dashboard.html ────────────────────────────────────────────
VULN_MAP_DASH = {
    'ftp':['Test anonymous FTP login (USER anonymous)','Check for FTP bounce attack','Banner grabbing - identify software version','Brute-force weak credentials','Test for cleartext credential sniffing (no TLS)'],
    'ssh':['Brute-force weak credentials (hydra/medusa)','Check for outdated SSH protocol version (SSHv1)','Test for weak host key algorithms (DSA 1024)','Username enumeration (timing-based)','Check for default/vendor credentials on appliances'],
    'telnet':['Capture cleartext credentials (wireshark/tcpdump)','Brute-force credentials','Banner grab for OS/version fingerprinting','Test for unauthenticated access'],
    'smtp':['Test for open relay (RCPT TO external domain)','VRFY/EXPN username enumeration','Banner grab for version','Check STARTTLS enforcement'],
    'smb':['Test for EternalBlue (MS17-010)','Check for null session / anonymous access (smbclient -N)','Enumerate shares (smbmap, crackmapexec)','Test for SMBv1 enabled','Brute-force credentials','Check for PrintNightmare (CVE-2021-1675)'],
    'rdp':['Test for BlueKeep (CVE-2019-0708)','Brute-force credentials (crowbar/ncrack)','Check NLA enforcement','Man-in-the-middle (missing NLA)','Check for DejaBlue (CVE-2019-1181/1182)'],
    'ldap':['Test for anonymous bind','Enumerate users/groups/OUs','Check for LDAP injection','Credential brute-force'],
    'snmp':['Test default community strings (public/private)','Enumerate via snmpwalk','Check for SNMPv1/v2 (cleartext)','Write access via community string'],
    'nfs':['List exports (showmount -e)','Mount without auth (no_root_squash)','Check world-readable/writable shares','Symlink attacks'],
    'mysql':['Test root with no password','Brute-force credentials','Check for UDF privilege escalation','SQL injection via exposed port'],
    'mssql':['Test SA account with blank/weak password','Enable xp_cmdshell for RCE','Check for linked servers','Brute-force credentials (Metasploit mssql_login)'],
    'postgresql':['Test postgres role with no password','Check pg_hba.conf trust entries','COPY TO/FROM PROGRAM for RCE','Brute-force credentials'],
    'redis':['Unauthenticated access (redis-cli ping)','CONFIG SET dir / dbfilename for RCE via SSH keys','Check for SLAVEOF replication abuse','Brute-force AUTH password'],
    'mongodb':['Test for authentication disabled','Enumerate databases without credentials','Check for NoSQL injection exposure','Network exposure (no TLS)'],
    'elasticsearch':['Unauthenticated access to /_cat/indices','Data exfiltration via REST API','RCE via Groovy/MVEL script injection (old versions)','Check for X-Pack security disabled'],
    'kibana':['Unauthenticated dashboard access','Check for Kibana CVE-2019-7609 (Timelion RCE)','Prototype pollution vulnerabilities','Access to Elasticsearch through Kibana proxy'],
    'vnc':['Test for no-authentication mode','Brute-force VNC password (4-byte key)','Screen capture without auth','Check LibVNCServer CVE exposure'],
    'printer':['Access embedded web server (default creds)','IPP job submission without auth','PJL filesystem traversal','SNMP printer MIB enumeration','Capture print jobs (cleartext)'],
    'imap':['Brute-force credentials','Check STARTTLS enforcement','Banner grab for version','Test for cleartext transmission'],
    'pop3':['Brute-force credentials','Check for STLS enforcement','Clear text credential capture'],
    'dns':['Zone transfer (dig AXFR)','DNS cache poisoning','DNS amplification (open resolver)','Subdomain enumeration'],
    'docker':['Unauthenticated Docker API (RCE risk)','Container escape via mounted /var/run/docker.sock','Check for privileged containers','Registry access without auth'],
    'kubernetes':['Unauthenticated API server access','Enumerate secrets/pods/namespaces','RBAC misconfiguration','etcd unauthenticated access','Kubelet read-only port (10255)'],
    'consul':['Unauthenticated HTTP API','Service mesh misconfiguration','Key/Value store data exposure','ACL bypass'],
    'prometheus':['Unauthenticated metrics endpoint','Internal network topology disclosure','PromQL injection'],
    'grafana':['Default admin:admin credentials','Check CVE-2021-43798 (path traversal)','SSRF via datasource configuration','Snapshot authentication bypass'],
    'rabbitmq':['Default guest:guest credentials','Management UI unauthenticated access','Message queue poisoning'],
    'rsync':['Unauthenticated module access','List modules (rsync --list-only)','File read/write without auth'],
    'oracle':['Default SID enumeration (tnscmd10g)','Brute-force credentials (oscanner)','TNS Listener poison attack','Check for default accounts (SCOTT/TIGER)'],
    'ntp':['NTP amplification/DRDoS','monlist query for reconnaissance','NTP mode 6/7 abuse'],
    'kerberos':['AS-REP Roasting (no pre-auth)','Kerberoasting (SPN enumeration)','Pass-the-ticket attacks','MS14-068 Kerberos PAC privilege escalation'],
    'mqtt':['Unauthenticated broker access','Subscribe to # wildcard topic','Brute-force credentials','Clear text credential capture'],
    'memcached':['Unauthenticated access','Memcached DRDoS amplification','Data exfiltration via stats command'],
    'citrix':['CVE-2019-19781 (Citrix ADC path traversal/RCE)','Brute-force credentials','Session token theft'],
    'http':['Directory/file brute-force (feroxbuster/gobuster)','Check for default credentials on admin panels','Test for SQLi, XSS, SSRF, XXE, IDOR','Check HTTP methods (PUT/DELETE/TRACE)','Missing security headers (CSP, HSTS, X-Frame)','Sensitive info in JS source / robots.txt / .git','Test for clickjacking','Check TLS configuration (sslscan/testssl.sh)'],
}

SVC_ICONS = {
    'http':'&#127760;','https':'&#128274;','ftp':'&#128193;','ssh':'&#128273;',
    'telnet':'&#128223;','smtp':'&#128231;','dns':'&#127757;','smb':'&#128450;',
    'rdp':'&#128421;','ldap':'&#128210;','snmp':'&#128225;','nfs':'&#128190;',
    'mysql':'&#128024;','mssql':'&#129695;','postgresql':'&#128024;','redis':'&#128308;',
    'mongodb':'&#127811;','elasticsearch':'&#128269;','kibana':'&#128202;',
    'kafka':'&#128232;','zookeeper':'&#129414;','imap':'&#128236;','pop3':'&#128238;',
    'vnc':'&#128444;','printer':'&#128424;','oracle':'&#128310;','cassandra':'&#128191;',
    'memcached':'&#9889;','rsync':'&#128260;','tftp':'&#128420;','ntp':'&#9201;',
    'kerberos':'&#127915;','bgp':'&#128376;','docker':'&#128051;','kubernetes':'&#9878;',
    'etcd':'&#128477;','consul':'&#127963;','prometheus':'&#128293;','grafana':'&#128200;',
    'influxdb':'&#128167;','rabbitmq':'&#128048;','mqtt':'&#128251;','citrix':'&#127970;',
}

def risk_for_svc(svc):
    high = {'smb','rdp','ftp','telnet','vnc','mssql','mysql','redis','mongodb',
            'elasticsearch','docker','kubernetes','nfs','ms-sql-s'}
    med  = {'ssh','smtp','snmp','ldap','postgresql','memcached','rabbitmq','mqtt',
            'rsync','oracle','http','https'}
    if svc in high: return 'high'
    if svc in med:  return 'medium'
    if 'http' in svc: return 'medium'
    return 'low'

# Build per-service rich data
svc_rich = {}
for e in data:
    svc = e['service'].lower()
    key = rev.get(svc, svc if svc else None)
    if not key: continue
    if key not in svc_rich:
        svc_rich[key] = {'entries': [], 'ip_set': set()}
    svc_rich[key]['entries'].append({'ip':e['ip'],'port':e['port'],'product':e['product'],'version':e['version']})
    svc_rich[key]['ip_set'].add(e['ip'])

# HTTP entries
http_entries = [{'ip':e['ip'],'port':e['port'],'product':e['product'],'version':e['version']} for e in data if is_http(e)]
if http_entries:
    svc_rich['http'] = {'entries': http_entries, 'ip_set': {e['ip'] for e in http_entries}}

# Load searchsploit results
ss_results = {}
ss_file = os.path.join(out_dir, 'searchsploit.txt')
if os.path.exists(ss_file):
    import re as _re
    raw_ss = open(ss_file).read()
    blocks = _re.split(r'[Oo]r? Searching for: ', raw_ss)
    for block in blocks[1:]:
        blines = block.split('\n')
        query = blines[0].strip()
        exploits = []
        in_table = False
        for ln in blines[1:]:
            if 'Exploit Title' in ln and '|' in ln:
                in_table = True; continue
            if in_table and '|' in ln and ln.strip() and not set(ln.strip()).issubset({'-','+',' ','|'}):
                parts = ln.split('|')
                if len(parts) >= 2:
                    title = parts[0].strip()
                    path  = parts[-1].strip()
                    if title and 'No Results' not in title and len(title) > 3:
                        exploits.append({'title': title, 'path': path})
        if exploits:
            ss_results[query] = exploits

import json as _json, datetime as _dt
now_str = _dt.datetime.now().strftime('%Y-%m-%d %H:%M')

# Build JS service array
js_services = []
for svc, info in sorted(svc_rich.items(), key=lambda x: -len(x[1]['ip_set'])):
    # Deduplicate entries
    seen = set()
    deduped = []
    for e in info['entries']:
        k = (e['ip'], e['port'])
        if k not in seen:
            seen.add(k); deduped.append(e)
    deduped.sort(key=lambda x: (list(map(int,x['ip'].split('.'))), int(x['port']) if x['port'].isdigit() else 0))

    # Components
    comps = {}
    for e in deduped:
        if e['product']:
            key2 = (e['product'] + ' ' + e['version']).strip()
            comps[key2] = comps.get(key2, 0) + 1

    # Exploits: match searchsploit results to this service
    svc_exploits = []
    seen_titles = set()
    for q, exps in ss_results.items():
        q_low = q.lower()
        if svc in q_low or any(e['product'].lower() in q_low for e in deduped if e['product']):
            for ex in exps:
                if ex['title'] not in seen_titles:
                    seen_titles.add(ex['title'])
                    svc_exploits.append(ex)

    vulns = VULN_MAP_DASH.get(svc, ['Manual review recommended'])
    icon  = SVC_ICONS.get(svc, '&#128295;')
    risk  = risk_for_svc(svc)
    ports = sorted({e['port'] for e in deduped}, key=lambda x: int(x) if x.isdigit() else 0)

    js_services.append({
        'svc': svc, 'icon': icon, 'risk': risk,
        'ip_count': len(info['ip_set']),
        'port_count': len(ports),
        'ports': ports,
        'entries': deduped,
        'components': [{'name':k,'count':v} for k,v in sorted(comps.items())],
        'vulns': vulns,
        'exploits': svc_exploits[:40],
    })

js_data_str = _json.dumps(js_services, ensure_ascii=True)
total_svcs  = len(js_services)
total_ips   = len({e['ip'] for s in js_services for e in s['entries']})
total_ports = sum(len(s['entries']) for s in js_services)

html_content = """

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SweepNinja Recon Dashboard</title>
<style>
:root{--bg:#0a0e17;--bg2:#0f1623;--bg3:#141c2e;--border:#1e2d47;
  --cyan:#00d4ff;--green:#00ff88;--yellow:#ffd600;--red:#ff4757;
  --orange:#ff6b35;--text:#c8d8f0;--text2:#7a90b0;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;min-height:100vh;}
header{background:var(--bg2);border-bottom:2px solid var(--cyan);padding:16px 28px;
  display:flex;align-items:center;justify-content:space-between;}
.logo{font-size:20px;font-weight:bold;color:var(--cyan);letter-spacing:3px;}
.logo em{color:var(--yellow);font-style:normal;}
.meta{font-size:10px;color:var(--text2);text-align:right;line-height:1.9;}
.statsbar{display:flex;gap:12px;padding:14px 28px;background:var(--bg2);
  border-bottom:1px solid var(--border);flex-wrap:wrap;}
.stat{background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  padding:10px 16px;min-width:110px;}
.stat-n{font-size:22px;font-weight:bold;color:var(--cyan);}
.stat-l{font-size:10px;color:var(--text2);text-transform:uppercase;letter-spacing:1px;}
.controls{padding:12px 28px;display:flex;gap:10px;align-items:center;
  flex-wrap:wrap;border-bottom:1px solid var(--border);}
.sort-btn{background:var(--bg3);border:1px solid var(--border);color:var(--text);
  padding:6px 14px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:11px;}
.sort-btn:hover,.sort-btn.active{border-color:var(--cyan);color:var(--cyan);}
.search-box{background:var(--bg3);border:1px solid var(--border);color:var(--text);
  padding:6px 12px;border-radius:6px;font-family:inherit;font-size:11px;
  outline:none;min-width:220px;}
.search-box:focus{border-color:var(--cyan);}
.risk-filter{display:flex;gap:6px;margin-left:auto;}
.rf-btn{padding:5px 12px;border-radius:20px;border:1px solid var(--border);
  cursor:pointer;font-size:10px;background:var(--bg3);color:var(--text2);}
.rf-btn.on-high{border-color:#ff4757;color:#ff4757;background:#ff475718;}
.rf-btn.on-med{border-color:#ffa502;color:#ffa502;background:#ffa50218;}
.rf-btn.on-low{border-color:#2ed573;color:#2ed573;background:#2ed57318;}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));
  gap:14px;padding:20px 28px;}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;
  overflow:hidden;display:flex;flex-direction:column;transition:transform .18s,border-color .18s;}
.card:hover{transform:translateY(-2px);border-color:var(--cyan);}
.card.r-high{border-left:3px solid #ff4757;}
.card.r-medium{border-left:3px solid #ffa502;}
.card.r-low{border-left:3px solid #2ed573;}
.card.hidden{display:none;}
.ch{padding:12px 14px;background:var(--bg3);display:flex;align-items:center;gap:9px;cursor:pointer;}
.ci{font-size:20px;width:30px;text-align:center;}
.cn{font-size:15px;font-weight:bold;color:var(--cyan);text-transform:uppercase;letter-spacing:1px;flex:1;}
.badge{font-size:9px;padding:2px 7px;border-radius:10px;font-weight:bold;}
.bh{background:#ff475720;color:#ff4757;border:1px solid #ff4757;}
.bm{background:#ffa50220;color:#ffa502;border:1px solid #ffa502;}
.bl{background:#2ed57320;color:#2ed573;border:1px solid #2ed573;}
.cstats{padding:9px 14px;display:flex;gap:18px;border-bottom:1px solid var(--border);}
.cs{text-align:center;}
.csn{font-size:18px;font-weight:bold;color:var(--yellow);}
.csl{font-size:9px;color:var(--text2);}
.cports{padding:7px 14px;display:flex;flex-wrap:wrap;gap:4px;border-bottom:1px solid var(--border);}
.ptag{background:var(--bg3);border:1px solid var(--border);border-radius:3px;
  font-size:10px;padding:1px 6px;color:var(--text2);}
.tabs{display:flex;border-bottom:1px solid var(--border);}
.tab{flex:1;padding:7px;text-align:center;font-size:10px;cursor:pointer;
  color:var(--text2);border-bottom:2px solid transparent;}
.tab.on{color:var(--cyan);border-bottom-color:var(--cyan);}
.tc{display:none;padding:10px 14px;max-height:260px;overflow-y:auto;}
.tc.on{display:block;}
.tc::-webkit-scrollbar{width:3px;}
.tc::-webkit-scrollbar-thumb{background:var(--border);}
.hr{display:flex;gap:7px;padding:3px 0;border-bottom:1px solid #1e2d4730;font-size:11px;align-items:baseline;}
.hip{color:var(--cyan);min-width:112px;}
.hpt{color:var(--yellow);min-width:42px;}
.hpd{color:var(--text2);font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.vi{padding:3px 0;font-size:11px;display:flex;gap:5px;}
.vi::before{content:">";color:var(--orange);flex-shrink:0;}
.er{padding:3px 0;border-bottom:1px solid #1e2d4730;}
.et{font-size:11px;color:#ff6b6b;}
.ep{font-size:10px;color:var(--text2);margin-top:1px;}
.cr{padding:3px 0;font-size:11px;display:flex;gap:7px;align-items:baseline;}
.cnm{color:var(--green);flex:1;}
.cct{color:var(--text2);font-size:10px;}
.mover{position:fixed;inset:0;background:#000c;z-index:100;
  display:none;align-items:center;justify-content:center;padding:16px;}
.mover.open{display:flex;}
.modal{background:var(--bg2);border:1px solid var(--cyan);border-radius:12px;
  width:100%;max-width:860px;max-height:88vh;overflow:hidden;display:flex;flex-direction:column;}
.mhead{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;}
.mtitle{font-size:16px;font-weight:bold;color:var(--cyan);flex:1;}
.mclose{background:none;border:none;color:var(--text2);font-size:18px;cursor:pointer;padding:2px 8px;}
.mclose:hover{color:var(--red);}
.mbody{overflow-y:auto;padding:18px;flex:1;}
.mbody::-webkit-scrollbar{width:4px;}
.mbody::-webkit-scrollbar-thumb{background:var(--border);}
.msec{margin-bottom:18px;}
.msec h3{font-size:12px;color:var(--yellow);text-transform:uppercase;letter-spacing:1px;
  margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid var(--border);}
.mtbl{width:100%;border-collapse:collapse;font-size:11px;}
.mtbl th{text-align:left;padding:5px 9px;color:var(--text2);font-size:9px;
  text-transform:uppercase;letter-spacing:1px;background:var(--bg3);}
.mtbl td{padding:5px 9px;border-bottom:1px solid var(--border);}
.mtbl tr:hover td{background:#ffffff06;}
footer{text-align:center;padding:18px;color:var(--text2);font-size:10px;
  border-top:1px solid var(--border);margin-top:16px;}
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">SWEEP<em>NINJA</em></div>
    <div style="font-size:10px;color:var(--text2);margin-top:3px;">Recon Intelligence Dashboard</div>
  </div>
  <div class="meta">Generated: GEN_DATE<br>Classification Report</div>
</header>

<div class="statsbar" id="sb"></div>

<div class="controls">
  <span style="font-size:10px;color:var(--text2);">SORT:</span>
  <button class="sort-btn active" onclick="doSort('ips',this)">Most IPs</button>
  <button class="sort-btn" onclick="doSort('ports',this)">Most Ports</button>
  <button class="sort-btn" onclick="doSort('name',this)">Name A-Z</button>
  <button class="sort-btn" onclick="doSort('risk',this)">Risk Level</button>
  <button class="sort-btn" onclick="doSort('exploits',this)">Has Exploits</button>
  <input class="search-box" type="text" placeholder="Filter by service, IP, product..." oninput="doFilter(this.value)" id="qbox">
  <div class="risk-filter">
    <button class="rf-btn" id="rf-high" onclick="toggleR('high')">HIGH</button>
    <button class="rf-btn" id="rf-med"  onclick="toggleR('medium')">MED</button>
    <button class="rf-btn" id="rf-low"  onclick="toggleR('low')">LOW</button>
  </div>
</div>

<div class="grid" id="grid"></div>

<div class="mover" id="mover" onclick="if(event.target===this)closeMod()">
  <div class="modal">
    <div class="mhead">
      <span id="micon" style="font-size:24px"></span>
      <div class="mtitle" id="mtitle"></div>
      <button class="mclose" onclick="closeMod()">X</button>
    </div>
    <div class="mbody" id="mbody"></div>
  </div>
</div>

<footer>SweepNinja v2.0 &nbsp;|&nbsp; GEN_DATE &nbsp;|&nbsp; TOTAL_SVCS services &nbsp;|&nbsp; TOTAL_IPS unique IPs &nbsp;|&nbsp; TOTAL_PORTS open ports</footer>

<script>
const SVC=JS_DATA_PLACEHOLDER;
let activeR=new Set();

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function renderStats(){
  const s=document.getElementById('sb');
  const uIPs=new Set(SVC.flatMap(x=>x.entries.map(e=>e.ip))).size;
  const uPts=SVC.reduce((a,x)=>a+x.entries.length,0);
  const hi=SVC.filter(x=>x.risk==='high').length;
  const ex=SVC.filter(x=>x.exploits.length>0).length;
  s.innerHTML=[[SVC.length,'Services'],[uIPs,'Unique IPs'],[uPts,'Open Ports'],
    [hi,'High Risk'],[ex,'w/ Exploits']]
    .map(([n,l])=>`<div class="stat"><div class="stat-n">${n}</div><div class="stat-l">${l}</div></div>`).join('');
}

function mkCard(s){
  const rc=`r-${s.risk}`, bc=s.risk==='high'?'bh':s.risk==='medium'?'bm':'bl';
  const pts=s.ports.slice(0,14).map(p=>`<span class="ptag">${p}</span>`).join('')+
    (s.ports.length>14?`<span class="ptag">+${s.ports.length-14}</span>`:'');
  const rows=s.entries.slice(0,300).map(e=>
    `<div class="hr"><span class="hip">${esc(e.ip)}</span><span class="hpt">:${esc(e.port)}</span><span class="hpd">${esc(e.product)} ${esc(e.version)}</span></div>`
  ).join('')+(s.entries.length>300?`<div style="color:var(--text2);font-size:10px;padding:5px">...${s.entries.length-300} more</div>`:'');
  const vulns=s.vulns.map(v=>`<div class="vi">${esc(v)}</div>`).join('');
  const exps=s.exploits.length
    ?s.exploits.map(x=>`<div class="er"><div class="et">${esc(x.title)}</div><div class="ep">${esc(x.path)}</div></div>`).join('')
    :'<div style="color:var(--text2);font-size:11px;padding:6px">No searchsploit results found.</div>';
  const comps=s.components.length
    ?s.components.map(c=>`<div class="cr"><span class="cnm">${esc(c.name)}</span><span class="cct">x${c.count} hosts</span></div>`).join('')
    :'<div style="color:var(--text2);font-size:11px">No version info.</div>';
  const exBadge=s.exploits.length?` <span style="color:#ff4757;font-size:9px">[${s.exploits.length}]</span>`:'';
  const id=s.svc.replace(/[^a-z0-9]/g,'_');
  return `<div class="card ${rc}" id="card_${id}" data-svc="${s.svc}" data-ips="${s.ip_count}" data-ports="${s.port_count}" data-risk="${s.risk}" data-ex="${s.exploits.length}">
  <div class="ch" onclick="openMod('${s.svc}')">
    <span class="ci">${s.icon}</span>
    <span class="cn">${esc(s.svc)}</span>
    <span class="badge ${bc}">${s.risk.toUpperCase()}</span>
  </div>
  <div class="cstats">
    <div class="cs"><div class="csn">${s.ip_count}</div><div class="csl">IPs</div></div>
    <div class="cs"><div class="csn">${s.port_count}</div><div class="csl">Ports</div></div>
    <div class="cs"><div class="csn">${s.exploits.length}</div><div class="csl">Exploits</div></div>
    <div class="cs"><div class="csn">${s.components.length}</div><div class="csl">Components</div></div>
  </div>
  <div class="cports">${pts}</div>
  <div class="tabs">
    <div class="tab on" onclick="swTab(this,'th_${id}')">Hosts</div>
    <div class="tab" onclick="swTab(this,'tv_${id}')">Vulns</div>
    <div class="tab" onclick="swTab(this,'te_${id}')">Exploits${exBadge}</div>
    <div class="tab" onclick="swTab(this,'tc_${id}')">Components</div>
  </div>
  <div class="tc on" id="th_${id}">${rows}</div>
  <div class="tc" id="tv_${id}">${vulns}</div>
  <div class="tc" id="te_${id}">${exps}</div>
  <div class="tc" id="tc_${id}">${comps}</div>
</div>`;
}

let curSort='ips';
function renderGrid(arr){document.getElementById('grid').innerHTML=arr.map(mkCard).join('');}

function doSort(by,btn){
  curSort=by;
  document.querySelectorAll('.sort-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  let a=[...SVC];
  if(by==='ips')      a.sort((x,y)=>y.ip_count-x.ip_count);
  if(by==='ports')    a.sort((x,y)=>y.port_count-x.port_count);
  if(by==='name')     a.sort((x,y)=>x.svc.localeCompare(y.svc));
  if(by==='risk')     {const o={high:0,medium:1,low:2};a.sort((x,y)=>o[x.risk]-o[y.risk]);}
  if(by==='exploits') a.sort((x,y)=>y.exploits.length-x.exploits.length);
  renderGrid(a);
  applyAll();
}

function doFilter(q){applyAll();}

function applyAll(){
  const q=document.getElementById('qbox').value.toLowerCase();
  document.querySelectorAll('.card').forEach(card=>{
    const s=SVC.find(x=>x.svc===card.dataset.svc);
    if(!s){return;}
    const matchQ=!q||s.svc.includes(q)||
      s.entries.some(e=>e.ip.includes(q)||e.port.includes(q)||(e.product+' '+e.version).toLowerCase().includes(q))||
      s.components.some(c=>c.name.toLowerCase().includes(q));
    const matchR=activeR.size===0||activeR.has(card.dataset.risk);
    card.classList.toggle('hidden',!matchQ||!matchR);
  });
}

function toggleR(r){
  const btnMap={high:'rf-high',medium:'rf-med',low:'rf-low'};
  const onMap={high:'on-high',medium:'on-med',low:'on-low'};
  if(activeR.has(r)){activeR.delete(r);}else{activeR.add(r);}
  document.getElementById(btnMap[r]).className='rf-btn'+(activeR.has(r)?' '+onMap[r]:'');
  applyAll();
}

function swTab(el,id){
  const card=el.closest('.card');
  card.querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));
  card.querySelectorAll('.tc').forEach(t=>t.classList.remove('on'));
  el.classList.add('on');
  document.getElementById(id).classList.add('on');
}

function openMod(sn){
  const s=SVC.find(x=>x.svc===sn);if(!s)return;
  document.getElementById('micon').innerHTML=s.icon;
  document.getElementById('mtitle').textContent=s.svc.toUpperCase()+' -- Full Details';
  const b=document.getElementById('mbody');
  const hrows=s.entries.map(e=>`<tr><td style="color:var(--cyan)">${esc(e.ip)}</td><td style="color:var(--yellow)">${esc(e.port)}</td><td style="color:var(--green);font-size:10px">${esc(e.product)} ${esc(e.version)}</td></tr>`).join('');
  const crows=s.components.length?s.components.map(c=>`<tr><td style="color:var(--green)">${esc(c.name)}</td><td style="color:var(--text2)">${c.count} host(s)</td></tr>`).join(''):'<tr><td colspan="2" style="color:var(--text2)">No version info detected.</td></tr>';
  const vrows=s.vulns.map(v=>`<li style="padding:3px 0;font-size:11px;color:var(--text)">${esc(v)}</li>`).join('');
  const erows=s.exploits.length?s.exploits.map(x=>`<tr><td style="color:#ff6b6b;font-size:11px">${esc(x.title)}</td><td style="color:var(--text2);font-size:10px">${esc(x.path)}</td></tr>`).join(''):'<tr><td colspan="2" style="color:var(--text2)">No exploits found.</td></tr>';
  b.innerHTML=`
    <div class="msec"><h3>All Hosts (${s.entries.length})</h3>
      <table class="mtbl"><thead><tr><th>IP Address</th><th>Port</th><th>Product / Version</th></tr></thead><tbody>${hrows}</tbody></table></div>
    <div class="msec"><h3>Components &amp; Versions</h3>
      <table class="mtbl"><thead><tr><th>Component</th><th>Hosts</th></tr></thead><tbody>${crows}</tbody></table></div>
    <div class="msec"><h3>Vulnerabilities to Test</h3>
      <ul style="list-style:none;padding:0">${vrows}</ul></div>
    <div class="msec"><h3>Searchsploit Results (${s.exploits.length})</h3>
      <table class="mtbl"><thead><tr><th>Exploit Title</th><th>Path</th></tr></thead><tbody>${erows}</tbody></table></div>`;
  document.getElementById('mover').classList.add('open');
}

function closeMod(){document.getElementById('mover').classList.remove('open');}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeMod();});

renderStats();
renderGrid(SVC);
</script>
</body>
</html>
"""

# Embed JSON directly inside const SVC=...
# Use re.sub with a lambda so Python never interprets backslashes in the JSON
# as regex/string escape sequences — the only safe way with arbitrary data.
import re as _re
json_str = _json.dumps(js_services, ensure_ascii=True)
# Make </script safe inside a <script> block
json_str = json_str.replace('</', '<\\/')
html_content = _re.sub(
    'const SVC=JS_DATA_PLACEHOLDER;',
    lambda m: 'const SVC=' + json_str + ';',
    html_content
)
html_content = html_content.replace('GEN_DATE', now_str)
html_content = html_content.replace('TOTAL_SVCS', str(total_svcs))
html_content = html_content.replace('TOTAL_IPS',  str(total_ips))
html_content = html_content.replace('TOTAL_PORTS',str(total_ports))

with open(os.path.join(out_dir, 'dashboard.html'), 'w', encoding='utf-8') as f:
    f.write(html_content)
print(f"  DASHBOARD    dashboard.html -> {total_svcs} service cards")

