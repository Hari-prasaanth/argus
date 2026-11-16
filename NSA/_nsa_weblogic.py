#!/usr/bin/env python3
import urllib.request,urllib.error,sys,signal,ssl,socket
signal.signal(signal.SIGINT,signal.SIG_IGN)
CTX=ssl.create_default_context();CTX.check_hostname=False;CTX.verify_mode=ssl.CERT_NONE
ENDPOINTS=["/wls-wsat/CoordinatorPortType","/wls-wsat/CoordinatorPortType11",
 "/wls-wsat/ParticipantPortType","/wls9_async_response/AsyncResponseService",
 "/wls9_async_response/AsyncResponseServiceJms"]
SOAP=b"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java><string>nsa_detection_probe</string></java>
    </work:WorkContext>
  </soapenv:Header><soapenv:Body/>
</soapenv:Envelope>"""
def fetch(url,method="GET",data=None,t=10):
 hdrs={"User-Agent":"Mozilla/5.0","Content-Type":"text/xml;charset=UTF-8","SOAPAction":'"detect"'}
 try:
  req=urllib.request.Request(url,data=data,headers=hdrs,method=method)
  with urllib.request.urlopen(req,timeout=t,context=CTX) as r:
   return r.read().decode("utf-8",errors="replace"),r.getcode()
 except urllib.error.HTTPError as e:
  try: body=e.read().decode("utf-8",errors="replace")
  except: body=""
  return body,e.code
 except: return "",0
def port_open(ip,port,t=5):
 try: s=socket.create_connection((ip,int(port)),timeout=t);s.close();return True
 except: return False
def check(ip,port):
 issues=[]
 if not port_open(ip,port): return []
 found=[]
 for scheme in ("http","https"):
  base=f"{scheme}://{ip}:{port}"
  for ep in ENDPOINTS:
   body,code=fetch(f"{base}{ep}",t=8)
   if code in (200,202,400,500) and any(w in body.lower() for w in
    ["wsat","weblogic","coordinatorporttype","wls","soapenv","xmlsoap"]):
    found.append(ep);break
  if found: break
 if not found:
  for scheme in ("http","https"):
   body,code=fetch(f"{scheme}://{ip}:{port}/",t=8)
   if code>0 and any(w in body.lower() for w in ["weblogic","oracle","wls"]):
    issues.append("WEBLOGIC_DETECTED:WebLogic server detected - verify CVE-2019-2729 manually")
    break
  return issues
 ep=found[0]
 for scheme in ("http","https"):
  body,code=fetch(f"{scheme}://{ip}:{port}{ep}",method="POST",data=SOAP,t=10)
  if code in (200,202,400,500):
   if any(w in body for w in ["WorkContext","bea.com","InputStream","ClassInfo"]):
    issues.append(f"CVE-2019-2729:Vulnerable - endpoint {ep} accepts XMLDecoder payload")
   else:
    issues.append(f"CVE-2019-2729:Endpoint {ep} exists (HTTP {code}) - likely vulnerable")
   break
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 sys.exit(0 if r else 1)
