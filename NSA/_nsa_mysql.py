#!/usr/bin/env python3
import subprocess,sys,signal,socket
signal.signal(signal.SIGINT,signal.SIG_IGN)
WCREDS=[("root",""),("root","root"),("root","toor"),("root","mysql"),("root","password"),("root","123456"),("admin","admin"),("admin",""),("mysql","mysql"),("mysql",""),("test","test"),("test","")]
def port_open(ip,port,t=5):
 try: s=socket.create_connection((ip,int(port)),timeout=t);s.close();return True
 except: return False
def mq(ip,port,u,p,q,t=8):
 try:
  pa=f"-p{p}" if p else ""
  r=subprocess.run(f"timeout {t} mysql -h {ip} -P {port} -u {u} {pa} -e \"{q}\" 2>/dev/null",
   shell=True,capture_output=True,text=True,timeout=t+2)
  return r.stdout+r.stderr
 except: return ""
def check(ip,port):
 issues=[]
 if not port_open(ip,port): return []
 fc=None
 for u,p in WCREDS:
  out=mq(ip,port,u,p,"SELECT 1;")
  if "1" in out and "ERROR" not in out: issues.append(f"WEAK_CREDS:{u}:{p if p else '<empty>'}");fc=(u,p);break
 if not fc: return []
 u,p=fc
 priv=mq(ip,port,u,p,"SHOW GRANTS;")
 if "ALL PRIVILEGES" in priv or "SUPER" in priv: issues.append("HIGH_PRIVS:Elevated privileges confirmed")
 pl=mq(ip,port,u,p,"SHOW VARIABLES LIKE 'plugin_dir';")
 if "plugin_dir" in pl: issues.append("UDF_POSSIBLE:UDF privesc via plugin_dir")
 sf=mq(ip,port,u,p,"SHOW VARIABLES LIKE 'secure_file_priv';")
 if "secure_file_priv" in sf:
  val=[l.split()[-1] for l in sf.splitlines() if "secure_file_priv" in l]
  if val and val[0] in ("","NULL","null"): issues.append("FILE_PRIV:secure_file_priv empty")
 ver=mq(ip,port,u,p,"SELECT version();")
 for l in ver.splitlines():
  if any(c.isdigit() for c in l) and "version" not in l.lower() and "ERROR" not in l:
   issues.append(f"VERSION:{l.strip()}");break
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 sys.exit(0 if r else 1)
