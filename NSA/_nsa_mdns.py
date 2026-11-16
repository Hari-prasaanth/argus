#!/usr/bin/env python3
"""mDNS Detection — Module 25
Sends DNS-SD queries to UDP 5353; checks for unicast responses.
Running mDNS on servers/infrastructure exposes hostname and services.
"""
import socket,struct,sys,signal,subprocess
signal.signal(signal.SIGINT,signal.SIG_IGN)

def build_sd_query(name="_services._dns-sd._udp.local", qtype=12):
    """DNS PTR query with QU bit (0x8001) requesting unicast response."""
    hdr = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    qname = b""
    for label in name.split("."):
        if label:
            qname += struct.pack("B", len(label)) + label.encode()
    qname += b"\x00"
    return hdr + qname + struct.pack(">HH", qtype, 0x8001)

def extract_name(data, offset, depth=0):
    if depth > 10: return "", offset
    parts = []
    visited = set()
    while offset < len(data):
        if offset in visited: break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1; break
        elif (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data): break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            sub, _ = extract_name(data, ptr, depth + 1)
            parts.append(sub); break
        else:
            offset += 1
            if offset + length > len(data): break
            parts.append(data[offset:offset+length].decode("utf-8", errors="replace"))
            offset += length
    return ".".join(parts), offset

def check(ip, port):
    issues = []

    # Primary: nmap dns-service-discovery
    try:
        out = subprocess.run(
            f"nmap -sU -p {port} --script dns-service-discovery -Pn -n {ip} 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=35
        )
        nmap_out = out.stdout + out.stderr
        if "dns-service-discovery" in nmap_out:
            svc_lines = [
                l.strip() for l in nmap_out.splitlines()
                if "|" in l and "dns-service-discovery" not in l
                and l.strip() not in ("|", "|_")
            ]
            if svc_lines:
                issues.append(
                    "MDNS_ENABLED:mDNS responding — hostname and services exposed "
                    "(information disclosure risk on infrastructure)"
                )
                issues.append(f"MDNS_SERVICES:{'; '.join(svc_lines[:6])}")
                return issues
    except:
        pass

    # Fallback: direct unicast UDP probe
    for qname in ["_services._dns-sd._udp.local", "local"]:
        try:
            pkt = build_sd_query(qname)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(pkt, (ip, int(port)))
            resp, _ = s.recvfrom(4096)
            s.close()
            if not resp or len(resp) < 12:
                continue
            rflags = struct.unpack(">H", resp[2:4])[0]
            if not (rflags & 0x8000):  # QR bit must be 1 (response)
                continue
            ancount = struct.unpack(">H", resp[6:8])[0]
            issues.append(
                "MDNS_ENABLED:mDNS unicast response received — "
                "information disclosure risk on infrastructure"
            )
            if ancount > 0:
                # Walk to first answer and extract name
                try:
                    pos = 12
                    qdcount = struct.unpack(">H", resp[4:6])[0]
                    for _ in range(qdcount):
                        while pos < len(resp):
                            if resp[pos] == 0: pos += 1; break
                            if resp[pos] & 0xC0 == 0xC0: pos += 2; break
                            pos += resp[pos] + 1
                        pos += 4  # skip qtype + qclass
                    name_found, _ = extract_name(resp, pos)
                    if name_found and "local" in name_found:
                        issues.append(f"MDNS_HOSTNAME:{name_found}")
                except:
                    pass
            return issues
        except:
            continue

    return issues

if __name__ == "__main__":
    if len(sys.argv) < 3: sys.exit(1)
    r = check(sys.argv[1], sys.argv[2])
    for x in r: print(x)
    vuln = [i for i in r if "MDNS_ENABLED" in i]
    sys.exit(0 if vuln else 1)
