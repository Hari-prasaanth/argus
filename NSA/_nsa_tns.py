#!/usr/bin/env python3
import socket,sys,signal,struct,subprocess
signal.signal(signal.SIGINT,signal.SIG_IGN)
def check_tns_poison(ip,port):
 try:
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(10)
  s.connect((ip,int(port)))
  connect_str=(f"(DESCRIPTION=(CONNECT_DATA=(SID=)(SERVER=dedicated)"
   f"(CID=(PROGRAM=probe)(HOST=probe)(USER=probe)))"
   f"(ADDRESS=(PROTOCOL=TCP)(HOST={ip})(PORT={port})))").encode()
  def ps(x):
   if x is None: return b"\xff\xff"
   return struct.pack(">H",len(x))+x+b"\x00"
  body=bytearray()
  body+=b"\x02"+ps(b"HTTP/1.1")+ps(b"/")+ps(b"127.0.0.1")+ps(b"probe")+ps(b"probe")
  body+=struct.pack(">H",8080)+b"\x00"+struct.pack(">H",0)+b"\xff"
  pkt=struct.pack(">BBH",0x12,0x34,len(body))+bytes(body)
  s.sendall(pkt)
  s.settimeout(8)
  hdr=s.recv(8)
  if not hdr or len(hdr)<8: s.close();return None
  ptype=hdr[4]
  length=struct.unpack(">H",hdr[:2])[0]
  rest=s.recv(max(0,length-8))
  if ptype==2:
   reg=(f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))"
    f"(CONNECT_DATA=(SERVICE_NAME=PROBE)(INSTANCE_NAME=PROBE)(SERVER=dedicated)))").encode()
   dp=struct.pack(">HHBBH",len(reg)+8,0,6,0,0)+reg
   s.sendall(dp)
   s.settimeout(8)
   hdr2=s.recv(8)
   s.close()
   if hdr2 and len(hdr2)>=5 and hdr2[4] in (2,6):
    return "VULNERABLE:Accepts remote instance registration (CVE-2012-1675)"
  s.close();return None
 except: return None
def get_ver(ip,port):
 try:
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(10)
  s.connect((ip,int(port)))
  cmd=b"(CONNECT_DATA=(COMMAND=VERSION))"
  pkt=struct.pack(">HHBBH",len(cmd)+8,0,1,0,0)+cmd
  s.sendall(pkt);s.settimeout(6);resp=s.recv(1024);s.close()
  if resp:
   import re;m=re.search(r"\d+\.\d+\.\d+\.\d+",resp.decode("utf-8",errors="replace"))
   if m: return m.group(0)
 except: pass
 return None
def check(ip,port):
 issues=[]
 ver=get_ver(ip,port)
 if ver: issues.append(f"TNS_VERSION:{ver}")
 try:
  out=subprocess.run(f"nmap -Pn -sT --script oracle-tns-poison -p {port} {ip} 2>/dev/null",
   shell=True,capture_output=True,text=True,timeout=30)
  nmap_out=out.stdout+out.stderr
  if "VULNERABLE" in nmap_out or "poison" in nmap_out.lower():
   issues.append("TNS_POISON:VULNERABLE via nmap oracle-tns-poison script");return issues
 except: pass
 result=check_tns_poison(ip,port)
 if result: issues.append(f"TNS_POISON:{result}")
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 vuln=[i for i in r if "TNS_POISON" in i]
 sys.exit(0 if vuln else 1)
