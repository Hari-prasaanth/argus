#!/usr/bin/env python3
import socket,struct,sys,signal,subprocess
signal.signal(signal.SIGINT,signal.SIG_IGN)
VULN_BUILDS={"1DB15F75","17725FAC","17714726","1773501D","1DB1446A","1DB14556",
 "1DB15CD4","1DB15EC5","1DB15D39","1DB154B9","1DB14A66","1DB15B4F",
 "17724D35","1DB04001","17714650","17724655","17724836","1772487D","1DB04228","1DB144E7"}
def dns_query(name,qtype=16,qclass=3):
 hdr=struct.pack(">HHHHHH",0xABCD,0x0100,1,0,0,0)
 qname=b""
 for label in name.split("."):
  qname+=struct.pack("B",len(label))+label.encode()
 qname+=b"\x00"
 return hdr+qname+struct.pack(">HH",qtype,qclass)
def send_udp(ip,port,pkt,t=5):
 try:
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(t)
  s.sendto(pkt,(ip,int(port)));data,_=s.recvfrom(4096);s.close();return data
 except: return None
def extract_txt(data):
 if not data or len(data)<12: return None
 try:
  ancount=struct.unpack(">H",data[6:8])[0]
  if ancount==0: return None
  pos=12
  while pos<len(data) and data[pos]!=0: pos+=1
  pos+=5
  while pos<len(data)-10 and ancount>0:
   if data[pos]&0xC0==0xC0: pos+=2
   else:
    while pos<len(data) and data[pos]!=0: pos+=1
    pos+=1
   if pos+10>len(data): break
   rtype,rclass,ttl,rdlen=struct.unpack(">HHIH",data[pos:pos+10]);pos+=10
   if rtype==16:
    td=data[pos:pos+rdlen];txt="";i=0
    while i<len(td):
     sl=td[i];i+=1;txt+=td[i:i+sl].decode("utf-8",errors="replace");i+=sl
    return txt
   pos+=rdlen;ancount-=1
 except: pass
 return None
def check(ip,port):
 issues=[]
 try:
  out=subprocess.run(f"nmap -sSU -p {port} --script cve-2020-1350 {ip} 2>/dev/null",
   shell=True,capture_output=True,text=True,timeout=35)
  nmap_out=out.stdout+out.stderr
  if "VULNERABLE" in nmap_out or "CVE-2020-1350" in nmap_out:
   bv=""
   for line in nmap_out.splitlines():
    if "bind.version" in line.lower(): bv=line.strip();break
   issues.append(f"CVE-2020-1350:SIGRED VULNERABLE{(' | '+bv) if bv else ''}");return issues
 except: pass
 resp=send_udp(ip,port,dns_query("version.bind",16,3))
 txt=extract_txt(resp) if resp else None
 if txt:
  issues.append(f"DNS_VERSION:{txt}")
  if any(b in txt.upper() for b in VULN_BUILDS):
   issues.append("CVE-2020-1350:SIGRED VULNERABLE - build matches known vulnerable version")
  elif "microsoft" in txt.lower():
   issues.append("CVE-2020-1350:Microsoft DNS detected - verify patch status manually")
 else:
  try:
   q2=dns_query("probe.test.local",1,1);r2=send_udp(ip,port,q2,t=4)
   if r2 and len(r2)>=12:
    issues.append("DNS_OPEN:DNS responding - version hidden, run nmap cve-2020-1350 for confirmation")
  except: pass
 return issues
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 r=check(sys.argv[1],sys.argv[2])
 for x in r: print(x)
 vuln=[i for i in r if "CVE-2020-1350" in i and "VULNERABLE" in i]
 sys.exit(0 if vuln else 1)
