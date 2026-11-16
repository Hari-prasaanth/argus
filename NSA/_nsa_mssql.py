#!/usr/bin/env python3
import subprocess,sys,signal,socket
signal.signal(signal.SIGINT,signal.SIG_IGN)
WCREDS=[("sa",""),("sa","sa"),("sa","password"),("sa","Password1"),("sa","123456"),("sa","admin"),("sa","sqlserver"),("admin","admin"),("admin","")]
def port_open(ip,port,t=5):
 try: s=socket.create_connection((ip,int(port)),timeout=t);s.close();return True
 except: return False
def mq(ip,port,u,p,q,t=12):
 try:
  pa=f"--script-args mssql.password={p}" if p else "--script-args mssql.password=''"
  cmd=(f"nmap -p {port} --script ms-sql-query --script-args mssql.username={u},{pa},"
       f"ms-sql-query.query=\"{q}\" -Pn {ip} 2>/dev/null")
  r=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=t+5)
  return r.stdout+r.stderr
 except: return ""
def check(ip,port):
 issues=[]
 if not port_open(ip,port): return []
 fc=None
 for u,p in WCREDS:
  out=mq(ip,port,u,p,"SELECT 1")
  if ("ms-sql-query" in out or "1" in out) and "Login failed" not in out and "ERROR" not in out:
   issues.append(f"WEAK_CREDS:{u}:{p if p else '<empty>'}");fc=(u,p);break
 if not fc:
  try:
   r=subprocess.run(f"nmap -p {port} --script ms-sql-brute -Pn {ip} 2>/dev/null",
    shell=True,capture_output=True,text=True,timeout=60)
   brute=r.stdout+r.stderr
   if "Credentials found" in brute or "Valid credentials" in brute:
    issues.append("WEAK_CREDS:Credentials found via brute")
  except: pass
  if not issues: return []
 if fc:
  u,p=fc
  co=mq(ip,port,u,p,"EXEC xp_cmdshell 'whoami'")
  if any(w in co for w in ["NT AUTHORITY","system","administrator"]):
   issues.append("XP_CMDSHELL:xp_cmdshell enabled - RCE")
  else:
   eo=mq(ip,port,u,p,"EXEC sp_configure 'show advanced options',1")
   if "Error" not in eo and "permission" not in eo.lower(): issues.append("XP_CMDSHELL_ENABLE:May be enableable")
  lo=mq(ip,port,u,p,"SELECT name FROM sys.servers WHERE is_linked=1")
  if lo.strip() and "Error" not in lo and "0 rows" not in lo: issues.append("LINKED_SERVERS:Linked servers exposed")
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 sys.exit(0 if r else 1)
