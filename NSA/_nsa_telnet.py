#!/usr/bin/env python3
import socket,sys,signal,time
signal.signal(signal.SIGINT,signal.SIG_IGN)
WCREDS=[("admin","admin"),("admin",""),("root","root"),("root",""),("admin","1234"),("admin","password"),("user","user"),("guest","guest"),("ubnt","ubnt"),("pi","raspberry"),("cisco","cisco"),("operator","operator")]
def ra(s,t=3):
 s.settimeout(t);data=b""
 try:
  while True:
   c=s.recv(4096)
   if not c: break
   data+=c
   if len(data)>8192: break
 except: pass
 return data.decode("utf-8",errors="replace")
def sr(s,txt,d=1.5):
 try: s.sendall((txt+"\r\n").encode());time.sleep(d);return ra(s,3)
 except: return ""
def check(ip,port):
 issues=[]
 try:
  s=socket.create_connection((ip,int(port)),timeout=10);b=ra(s,5);s.close()
  if b:
   issues.append(f"BANNER:{b.replace(chr(10),' ').replace(chr(13),'')[:150]}")
   issues.append("CLEARTEXT:Telnet is cleartext")
  else: return []
 except: return []
 try:
  s=socket.create_connection((ip,int(port)),timeout=10);ra(s,3);r=sr(s,"",2)
  if r and any(c in r for c in ["$","#",">"]): issues.append("UNAUTH_ACCESS:Shell without credentials")
  s.close()
 except: pass
 for u,p in WCREDS:
  try:
   s=socket.create_connection((ip,int(port)),timeout=10);b=ra(s,5)
   if any(w in b.lower() for w in ["login","username","user"]):
    r1=sr(s,u,1.5)
    if any(w in r1.lower() for w in ["password","pass"]):
     r2=sr(s,p,2.0)
     if any(c in r2 for c in ["$","#",">"]) or any(w in r2.lower() for w in ["welcome","last login"]):
      issues.append(f"WEAK_CREDS:{u}:{p if p else '<empty>'}");s.close();break
   s.close()
  except: pass
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 vulns=[x for x in r if not x.startswith("BANNER:")]
 sys.exit(0 if vulns else 1)
