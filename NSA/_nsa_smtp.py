#!/usr/bin/env python3
import socket,sys,random,string,signal
signal.signal(signal.SIGINT,signal.SIG_IGN)
CT=15;RT=30;BUF=4096
USERS=["adm","admin","administrator","anonymous","apache","backup","bin","daemon",
 "dbus","ftp","games","gdm","guest","halt","hr","imap","info","it","kali","lp",
 "mail","marketing","mysql","netadmin","news","nginx","nobody","noc","ntp","office",
 "operator","oracle","pi","pop","postgres","postmaster","rpc","sales","security",
 "service","shutdown","smtp","sshd","staff","support","sync","sys","sysadmin",
 "tcpdump","test","ubnt","uucp","user","vagrant","web","webmaster","www","www-data"]
def r8(): return "".join(random.choices(string.ascii_lowercase,k=8))
class C:
 def __init__(s,ip,p): s.ip,s.port,s.s=ip,p,None
 def connect(s):
  s.s=socket.socket();s.s.settimeout(CT);s.s.connect((s.ip,s.port));s.s.settimeout(RT);return s._r()
 def close(s):
  try: s.s.close()
  except: pass
  s.s=None
 def _r(s):
  try: return s.s.recv(BUF).decode("utf-8",errors="replace").strip()
  except: return ""
 def send(s,c):
  try:
   s.s.sendall(c.encode());r=s._r()
   if not r: return "",0
   return r,(int(r[:3]) if r[:3].isdigit() else 0)
  except: return "",0
 def reconnect(s,c):
  s.close()
  try: s.connect();s.send("HELO localhost\r\n");return s.send(c)
  except: return "",0
def ve(conn,m):
 found=[]
 for u in USERS:
  if u=="root": continue
  c=f"{m} {u}\r\n";r,code=conn.send(c)
  if code==0 and not r: r,code=conn.reconnect(c)
  if code==250: found.append(u)
 return found
def re(conn,domain):
 found=[]
 for u in USERS:
  if u=="root": continue
  mc=f"MAIL FROM: root@{domain}\r\n";r,code=conn.send(mc)
  if code==0: conn.reconnect(mc);r,code=conn.send(mc)
  if code!=250: break
  rc=f"RCPT TO: {u}@{domain}\r\n";r,code=conn.send(rc)
  if code==0: conn.reconnect(mc);r,code=conn.send(rc)
  if code==250: found.append(u)
  conn.send("RSET\r\n")
 return found
def run(ip,port):
 conn=C(ip,port)
 try: banner=conn.connect()
 except: return 1,[]
 if not banner or "microsoft" in banner.lower(): conn.close();return 1,[]
 r,_=conn.send("HELO localhost\r\n")
 if not r: conn.close();return 1,[]
 parts=r.split();domain=parts[1] if len(parts)>1 else "localhost"
 found,method="",""
 _,vc=conn.send("VRFY root\r\n")
 if vc==250: found=ve(conn,"VRFY");method="VRFY" if found else ""
 if not found:
  _,ec=conn.send("EXPN root\r\n")
  if ec==250: found=ve(conn,"EXPN");method="EXPN" if found else ""
 if not found:
  _,mc=conn.send(f"MAIL FROM: root@{domain}\r\n")
  if mc==250:
   _,rc=conn.send(f"RCPT TO: {r8()}@{domain}\r\n");conn.send("RSET\r\n")
   if not (250<=rc<=259): conn.send("RSET\r\n");found=re(conn,domain);method="RCPT" if found else ""
 conn.close()
 if found:
  print(f"INFO:banner:{banner[:120]}");print(f"METHOD:{method}")
  for u in found: print(f"USER:{u}")
  return 0,found
 return 1,[]
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 s,_=run(sys.argv[1],int(sys.argv[2]));sys.exit(s)
