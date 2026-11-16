#!/usr/bin/env python3
import subprocess,sys,tempfile,shutil,signal
signal.signal(signal.SIGINT,signal.SIG_IGN)
def run(cmd,t=10):
 try: r=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=t);return r.stdout+r.stderr
 except: return ""
def check(ip,port):
 out=run(f"showmount -e {ip} --no-headers 2>/dev/null",15)
 if not out.strip(): return []
 exports=[l.split()[0] for l in out.strip().splitlines() if l.split()]
 if not exports: return []
 issues=[f"EXPORT_FOUND:{','.join(exports)}"]
 if "*" in out or "(everyone)" in out.lower() or "0.0.0.0" in out: issues.append("WORLD_ACCESSIBLE")
 tmpdir=tempfile.mkdtemp(prefix="nsa_")
 try:
  for e in exports[:3]:
   mo=run(f"timeout 8 mount -t nfs -o nolock,ro {ip}:{e} {tmpdir} 2>&1",12)
   if "denied" not in mo.lower() and "failed" not in mo.lower():
    mc=run(f"mountpoint -q {tmpdir} 2>/dev/null && echo YES",5)
    if "YES" in mc:
     issues.append(f"MOUNT_SUCCESS:{e}")
     lo=run(f"find {tmpdir} -maxdepth 2 -perm -o+w 2>/dev/null | head -5",8)
     if lo.strip(): issues.append("WORLD_WRITABLE")
     run(f"umount -f {tmpdir} 2>/dev/null",5);break
 finally: shutil.rmtree(tmpdir,ignore_errors=True)
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 sys.exit(0 if r else 1)
