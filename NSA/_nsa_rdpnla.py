#!/usr/bin/env python3
"""RDP - Terminal Services NLA enforcement check (Module 24)
Verify command: nmap -p PORT --script rdp-enum-encryption -Pn TARGET
Vulnerable if: server accepts Classic RDP or TLS-only without CredSSP/NLA,
               or allows Classic RDP fallback when NLA is offered.
"""
import socket,struct,sys,signal,subprocess
signal.signal(signal.SIGINT,signal.SIG_IGN)

# X.224 Connection Request — ask for all protocols: TLS(1) + CredSSP(2) = 0x03
RDP_ALL     = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
# X.224 Connection Request — ask for Classic RDP only (protocol = 0x00)
RDP_CLASSIC = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00"
PROTO = {0:"Classic RDP (no TLS/NLA)", 1:"TLS only", 2:"CredSSP/NLA", 8:"CredSSP+EUA"}

def port_open(ip, port, t=5):
    try: s=socket.create_connection((ip,int(port)),timeout=t); s.close(); return True
    except: return False

def rdp_probe(ip, port, pkt, t=10):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(t)
        s.connect((ip,int(port))); s.sendall(pkt); s.settimeout(8)
        resp=s.recv(1024); s.close(); return resp
    except: return b""

def parse_cc(resp):
    """Parse X.224 Connection Confirm.
    Byte 11 = RDP Negotiation type: 0x02=Response, 0x03=Failure
    Bytes 15-18 = selectedProtocol / failureCode (little-endian uint32)
    """
    if not resp or len(resp)<19 or resp[0]!=0x03: return None,None
    nt = resp[11] if len(resp)>11 else 0
    if nt==0x02 and len(resp)>=19: return "RSP", struct.unpack("<I",resp[15:19])[0]
    if nt==0x03 and len(resp)>=19: return "FAIL", struct.unpack("<I",resp[15:19])[0]
    return None,None

def check(ip, port):
    issues = []
    vcmd = f"nmap -p {port} --script rdp-enum-encryption -Pn {ip}"

    if not port_open(ip, int(port)):
        return []

    # Step 1 — send negotiation request asking for all protocols
    resp = rdp_probe(ip, port, RDP_ALL)
    nt, proto = parse_cc(resp)
    nla_enforced = True

    if nt == "RSP":
        pd = PROTO.get(proto, f"Unknown(0x{proto:x})")
        if proto == 0:
            # Server selected Classic RDP — NLA not enforced, connection succeeds
            nla_enforced = False
            issues.append(
                f"NO_NLA:Classic RDP connection accepted — NLA not enforced "
                f"(selected: {pd}). Verify: {vcmd}"
            )
            issues.append(
                "CREDENTIAL_RISK:Credentials transmitted without NLA — "
                "subject to MitM / credential interception"
            )
        elif proto == 1:
            # TLS offered but no CredSSP — NLA still not enforced
            nla_enforced = False
            issues.append(
                f"NO_NLA:Server selected TLS-only ({pd}), CredSSP/NLA not "
                f"offered — NLA not enforced. Verify: {vcmd}"
            )
        elif proto in (2, 8):
            # Server offered NLA — check if Classic RDP fallback still works
            resp2 = rdp_probe(ip, port, RDP_CLASSIC)
            nt2, proto2 = parse_cc(resp2)
            if nt2 == "RSP" and proto2 == 0:
                nla_enforced = False
                issues.append(
                    f"NLA_BYPASS:Classic RDP fallback accepted despite NLA offer — "
                    f"NLA bypassable. Verify: {vcmd}"
                )
    elif resp:
        # Got a response but couldn't parse the CC — port is open
        issues.append(f"RDP_OPEN:RDP responding — negotiation inconclusive; run: {vcmd}")

    # Step 2 — cross-validate with nmap rdp-enum-encryption
    try:
        out = subprocess.run(
            f"nmap -p {port} --script rdp-enum-encryption -Pn -n {ip} 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=30
        )
        nmap_out = out.stdout + out.stderr
        if "rdp-enum-encryption" in nmap_out:
            enc_lines = [
                l.strip() for l in nmap_out.splitlines()
                if "|" in l and "rdp-enum-encryption" not in l
                and l.strip() not in ("|", "|_")
            ]
            if enc_lines:
                issues.append(f"ENC_DETAILS:{'; '.join(enc_lines[:5])}")
            # If nmap also sees no NLA and we thought it was enforced, flag it
            has_nla_nmap = "CredSSP" in nmap_out or "NLA" in nmap_out
            if not has_nla_nmap and nla_enforced and enc_lines:
                issues.append(
                    f"NO_NLA:nmap confirms no CredSSP/NLA in encryption scan — "
                    f"NLA not enforced. Verify: {vcmd}"
                )
                nla_enforced = False
    except:
        pass

    return issues

if __name__ == "__main__":
    if len(sys.argv) < 3: sys.exit(1)
    r = check(sys.argv[1], sys.argv[2])
    for x in r: print(x)
    vuln = [i for i in r if any(k in i for k in ["NO_NLA","NLA_BYPASS","CREDENTIAL_RISK"])]
    sys.exit(0 if vuln else 1)
