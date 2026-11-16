#!/usr/bin/env python3
import subprocess,sys,signal
signal.signal(signal.SIGINT,signal.SIG_IGN)
def run(cmd,t=30):
 try: r=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=t);return r.stdout+r.stderr
 except: return ""
def check(ip,port):
 issues=[]
 bk=run(f"nmap -p {port} --script rdp-vuln-ms12-020,rdp-enum-encryption -Pn -n {ip} 2>/dev/null",35)
 if "VULNERABLE" in bk or "CVE-2019-0708" in bk: issues.append("BLUEKEEP:CVE-2019-0708 VULNERABLE")
 enc=run(f"nmap -p {port} --script rdp-enum-encryption -Pn -n {ip} 2>/dev/null",25)
 if enc and "NLA" not in enc and ("Security Layer" in enc or "RDP" in enc):
  issues.append("NO_NLA:NLA not enforced")
 if "Classic RDP Security" in enc or "ENCRYPTION_METHOD_NONE" in enc:
  issues.append("WEAK_ENC:Weak/no encryption")
 ver=run(f"nmap -p {port} -sV -Pn -n {ip} 2>/dev/null",20)
 if "Windows" in ver and any(w in ver for w in ["7","10","2008","2016"]):
  issues.append("DEJABLUE:CVE-2019-1181/1182 possible")
 nc=run("which ncrack 2>/dev/null",3)
 if nc.strip():
  bf=run(f"ncrack -p {port} --user administrator,admin,guest --pass '' {ip} 2>/dev/null",25)
  if "Discovered credentials" in bf:
   issues.append("WEAK_CREDS:Credentials found")
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 sys.exit(0 if r else 1)
