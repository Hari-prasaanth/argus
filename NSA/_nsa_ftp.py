#!/usr/bin/env python3
import socket,sys,signal,ftplib
signal.signal(signal.SIGINT,signal.SIG_IGN)
WCREDS=[("ftp","ftp"),("admin","admin"),("admin",""),("root","root"),("root",""),("user","user"),("test","test"),("guest","guest")]
def banner(ip,port,t=10):
 try:
  s=socket.create_connection((ip,port),timeout=t);s.settimeout(t)
  b=s.recv(1024).decode("utf-8",errors="replace").strip();s.close();return b
 except: return ""
def has_tls(ip,port,t=10):
 try: f=ftplib.FTP_TLS(timeout=t);f.connect(ip,port);f.auth();f.quit();return True
 except: return False
def check(ip,port):
 issues=[]
 b=banner(ip,port)
 if not b: return []
 issues.append(f"BANNER:{b[:120].replace(chr(10),' ').replace(chr(13),'')}")
 if not has_tls(ip,port): issues.append("CLEARTEXT:No TLS - credentials in plaintext")
 try:
  f=ftplib.FTP(timeout=10);f.connect(ip,port);f.login("anonymous","anonymous@")
  issues.append("ANON_LOGIN:Anonymous FTP login allowed")
  try:
   files=f.nlst()
   if files: issues.append(f"ANON_FILES:{len(files)} items accessible")
  except: pass
  try: f.sendcmd("PORT 127,0,0,1,0,21");issues.append("FTP_BOUNCE:Bounce attack possible")
  except: pass
  f.quit()
 except: pass
 for u,p in WCREDS:
  try:
   f=ftplib.FTP(timeout=8);f.connect(ip,port);f.login(u,p)
   issues.append(f"WEAK_CREDS:{u}:{p if p else '<empty>'}");f.quit();break
  except: pass
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],int(sys.argv[2]))
 for x in r: print(x)
 vulns=[x for x in r if not x.startswith("BANNER:")]
 sys.exit(0 if vulns else 1)
