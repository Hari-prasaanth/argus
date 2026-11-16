#!/usr/bin/env python3
import subprocess,sys,signal
signal.signal(signal.SIGINT,signal.SIG_IGN)
def run(cmd,t=25):
 try: r=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=t);return r.stdout+r.stderr
 except: return ""
def check(ip,port):
 issues=[]
 nb=run(f"nmblookup -A {ip} 2>/dev/null",10)
 if nb and "<00>" in nb:
  names=[l.strip() for l in nb.splitlines() if "<" in l and "ACTIVE" in l]
  if names: issues.append(f"NETBIOS_NAMES:{'; '.join(names[:5])}")
 null=run(f"smbclient -L //{ip} -N -p {port} 2>/dev/null",15)
 if "Sharename" in null or "IPC$" in null:
  issues.append("NULL_SESSION:Anonymous/null session allowed")
  shares=[l.strip() for l in null.splitlines() if any(t in l for t in ["Disk","IPC","Printer"])]
  if shares: issues.append(f"SHARES_FOUND:{'; '.join(shares[:6])}")
 users_out=run(f"nmap -p {port} --script smb-enum-users -Pn {ip} 2>/dev/null",30)
 if "smb-enum-users" in users_out:
  ul=[l.strip() for l in users_out.splitlines()
   if l.strip() and "|" in l and "smb-enum-users" not in l and "account_used" not in l and l.strip()!="|"]
  if ul:
   issues.append(f"USERS_ENUM:{len(ul)} user(s) enumerated anonymously")
   issues.append(f"USER_LIST:{'; '.join(ul[:5])}")
 shares_out=run(f"nmap -p {port} --script smb-enum-shares -Pn {ip} 2>/dev/null",30)
 if "Anonymous access:" in shares_out:
  as_=[l.strip() for l in shares_out.splitlines() if "Anonymous access:" in l and "<none>" not in l]
  if as_: issues.append(f"ANON_SHARES:{'; '.join(as_[:5])}")
 os_out=run(f"nmap -p {port} --script smb-os-discovery -Pn {ip} 2>/dev/null",20)
 if "smb-os-discovery" in os_out:
  for line in os_out.splitlines():
   if any(k in line for k in ["OS:","Computer name:","Domain name:"]):
    issues.append(f"OS_INFO:{line.strip().lstrip('|').strip()}")
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 vuln=[i for i in r if any(k in i for k in ["NULL_SESSION","USERS_ENUM","ANON_SHARES","NETBIOS_NAMES"])]
 sys.exit(0 if vuln else 1)
