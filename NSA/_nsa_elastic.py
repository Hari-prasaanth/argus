#!/usr/bin/env python3
import urllib.request,urllib.error,json,sys,signal,ssl
signal.signal(signal.SIGINT,signal.SIG_IGN)
CTX=ssl.create_default_context();CTX.check_hostname=False;CTX.verify_mode=ssl.CERT_NONE
def fetch(url,t=10):
 try:
  req=urllib.request.Request(url,headers={"User-Agent":"Mozilla/5.0"})
  with urllib.request.urlopen(req,timeout=t,context=CTX) as r:
   return r.read().decode("utf-8",errors="replace"),r.getcode()
 except urllib.error.HTTPError as e: return "",e.code
 except: return "",0
def check(ip,port):
 issues=[];base=""
 for scheme in ("http","https"):
  body,code=fetch(f"{scheme}://{ip}:{port}/",8)
  if code==200 and ("elasticsearch" in body.lower() or "cluster_name" in body.lower()):
   try:
    data=json.loads(body);ver=data.get("version",{}).get("number","unknown")
    issues.append(f"UNAUTH_ACCESS:Accessible without auth (v{ver})")
   except: issues.append("UNAUTH_ACCESS:Accessible without auth")
   base=f"{scheme}://{ip}:{port}";break
  elif code in (401,403): return []
 if not issues: return []
 _,hc=fetch(f"{base}/_cluster/health",8)
 if hc==200: issues.append("CLUSTER_HEALTH:/_cluster/health exposed")
 ib,ic=fetch(f"{base}/_cat/indices?v",8)
 if ic==200 and ("index" in ib.lower() or "green" in ib):
  n=len([l for l in ib.splitlines() if l.strip() and not l.startswith("health")])
  issues.append(f"DATA_EXPOSURE:{n} indices readable")
 xb,xc=fetch(f"{base}/_xpack",8)
 if xc==200:
  if '"enabled":false' in xb: issues.append("XPACK_DISABLED:X-Pack security disabled")
  else: issues.append("XPACK_EXPOSED:X-Pack readable without auth")
 try:
  gp=b'{"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"t":{"script":"java.lang.Math.class.forName(\\"java.lang.Runtime\\")","lang":"groovy"}}}'
  req=urllib.request.Request(f"{base}/_search",data=gp,
   headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"},method="POST")
  with urllib.request.urlopen(req,timeout=8,context=CTX) as r:
   gb=r.read().decode("utf-8",errors="replace")
   if "Runtime" in gb or "script_fields" in gb: issues.append("GROOVY_RCE:Groovy RCE risk (CVE-2014-3120)")
 except: pass
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 sys.exit(0 if r else 1)
