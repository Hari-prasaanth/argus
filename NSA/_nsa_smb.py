#!/usr/bin/env python3
import subprocess,sys,signal
signal.signal(signal.SIGINT,signal.SIG_IGN)
def run(cmd,t=25):
 try: r=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=t);return r.stdout+r.stderr
 except: return ""
def check(ip,port):
 issues=[]
 eb=run(f"nmap -p {port} --script smb-vuln-ms17-010 -Pn -n {ip} 2>/dev/null",35)
 if "VULNERABLE" in eb or "State: VULNERABLE" in eb: issues.append("ETERNALBLUE:MS17-010 VULNERABLE")
 null=run(f"smbclient -L //{ip} -N -p {port} 2>/dev/null",15)
 if "Sharename" in null or "IPC$" in null: issues.append("NULL_SESSION:Anonymous access allowed")
 sm=run(f"smbmap -H {ip} -P {port} 2>/dev/null",20)
 if "READ" in sm or "WRITE" in sm:
  rd=[l.strip() for l in sm.splitlines() if "READ" in l or "WRITE" in l]
  issues.append(f"SHARES:{'; '.join(rd[:5])}")
 v1=run(f"nmap -p {port} --script smb-protocols -Pn -n {ip} 2>/dev/null",20)
 if "SMBv1" in v1 and "enabled" in v1.lower(): issues.append("SMBV1:SMBv1 enabled")
 rpc=run(f"rpcdump.py {ip} 2>/dev/null | grep -i '4d9f4ab8-7d1c-11cf-861e-0020af6e7c57'",15)
 if rpc.strip(): issues.append("PRINTNIGHTMARE:Spooler exposed (CVE-2021-1675)")
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 sys.exit(0 if r else 1)
