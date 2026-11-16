#!/usr/bin/env python3
# NSA Web — minimalist local web UI for the Network Security Auditor engine.
# The scanning modules/probes are UNCHANGED (the _nsa_*.py files in ./NSA).
# This file only replaces the interactive bash menu with a local web front-end.
#
# Run:  python3 nsa_web.py            (binds 127.0.0.1:8777, opens browser)
#       python3 nsa_web.py --port 9000 --no-browser
#
# SECURITY: binds to localhost only. This page executes scan commands on the
# host it runs on. Never expose it on a reachable interface.

import os, sys, re, json, html, shlex, shutil, subprocess, threading, time, uuid, argparse, webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "NSA")          # main folder (probes + saved output)
PROBE_DIR  = OUTPUT_DIR
TARGET_RE  = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
PER_TARGET_TIMEOUT = 300                            # seconds, per host per module

# Info-only probe keys (details, NOT a vulnerability) — mirrors run_scan() in NSA_full.sh
INFO_KEYS = {
    "BANNER","TNS_VERSION","DNS_VERSION","PAGE_COUNT","VERSION","OS_INFO","ENC_DETAILS",
    "RDP_OPEN","DNS_OPEN","PJL_STATUS","USER_LIST","SHARES_FOUND","WEBLOGIC_DETECTED",
}

# ── Module registry (mirrors get_module_name / get_default_port / get_module_filename) ──
# runner: "cmd"  -> run argv, classify by markers in output (modules 1-6)
#         "probe"-> run _nsa_*.py, classify by non-info output lines (modules 9-25)
#         "ipmi" / "smtp" -> msfconsole if present else probe (modules 7-8)
MODULES = {
    1:  dict(name="NTP Monlist (DoS Amplification)",                 cat="Network Services", port=123,  slug="ntp_monlist",      runner="cmd"),
    2:  dict(name="NTP Mode 6 Scanner",                              cat="Network Services", port=123,  slug="ntp_mode6",        runner="cmd"),
    3:  dict(name="SNMP Default Community String",                   cat="Network Services", port=161,  slug="snmp",             runner="cmd"),
    4:  dict(name="SMB Signing Disabled",                            cat="Auth & Hashing",   port=445,  slug="smb_signing",      runner="cmd"),
    5:  dict(name="AMQP Cleartext Authentication",                   cat="Network Services", port=5672, slug="amqp",             runner="cmd"),
    6:  dict(name="Redis Unauthenticated Access",                    cat="Network Services", port=6379, slug="redis",            runner="cmd"),
    7:  dict(name="IPMI v2.0 RAKP Hash Disclosure",                  cat="Auth & Hashing",   port=623,  slug="ipmi",             runner="ipmi"),
    8:  dict(name="SMTP User Enumeration",                           cat="Auth & Hashing",   port=25,   slug="smtp_enum",        runner="smtp"),
    9:  dict(name="NFS Export / Mount / World-Writable",             cat="File Sharing",     port=2049, slug="nfs",              runner="probe", probe="_nsa_nfs.py"),
    10: dict(name="SMB Advanced (EternalBlue/PrintNightmare)",       cat="File Sharing",     port=445,  slug="smb_advanced",     runner="probe", probe="_nsa_smb.py"),
    11: dict(name="RDP Security (BlueKeep/NLA/DejaBlue)",            cat="Remote Access",    port=3389, slug="rdp",              runner="probe", probe="_nsa_rdp.py"),
    12: dict(name="FTP (Anonymous/Bounce/Cleartext/Brute)",          cat="Remote Access",    port=21,   slug="ftp",              runner="probe", probe="_nsa_ftp.py"),
    13: dict(name="MySQL (Root No-Pass/UDF Privesc/Brute)",          cat="Databases",        port=3306, slug="mysql",            runner="probe", probe="_nsa_mysql.py"),
    14: dict(name="Telnet (Cleartext/Brute/Unauthenticated)",        cat="Remote Access",    port=23,   slug="telnet",           runner="probe", probe="_nsa_telnet.py"),
    15: dict(name="MSSQL (SA Account/xp_cmdshell/Linked Servers)",   cat="Databases",        port=1433, slug="mssql",            runner="probe", probe="_nsa_mssql.py"),
    16: dict(name="Elasticsearch (Unauth/Data Exposure/RCE)",        cat="Databases",        port=9200, slug="elasticsearch",    runner="probe", probe="_nsa_elastic.py"),
    17: dict(name="F5 BIG-IP (CVE-2020-5902/2021-22986/2022-1388)",  cat="App / Middleware", port=443,  slug="f5_bigip",         runner="probe", probe="_nsa_f5.py"),
    18: dict(name="Oracle WebLogic CVE-2019-2729 Deserialization",   cat="App / Middleware", port=7001, slug="oracle_weblogic",  runner="probe", probe="_nsa_weblogic.py"),
    19: dict(name="Oracle TNS Listener Poison CVE-2012-1675",        cat="Databases",        port=1521, slug="oracle_tns",       runner="probe", probe="_nsa_tns.py"),
    20: dict(name="Printer PJL Unauthenticated Code Execution",      cat="App / Middleware", port=9100, slug="printer_pjl",      runner="probe", probe="_nsa_pjl.py"),
    21: dict(name="Apache Ghostcat CVE-2020-1938 AJP File Read",     cat="App / Middleware", port=8009, slug="apache_ghostcat",  runner="probe", probe="_nsa_ghostcat.py"),
    22: dict(name="SIGRed CVE-2020-1350 Windows DNS RCE",            cat="App / Middleware", port=53,   slug="sigred_dns",       runner="probe", probe="_nsa_sigred.py"),
    23: dict(name="LANMAN Null Session (Users/Shares/Services)",     cat="File Sharing",     port=445,  slug="lanman",           runner="probe", probe="_nsa_lanman.py"),
    24: dict(name="Terminal Services - NLA Not Enforced",            cat="Remote Access",    port=3389, slug="rdp_nla",          runner="probe", probe="_nsa_rdpnla.py"),
    25: dict(name="mDNS Detection (Information Disclosure)",          cat="Network Services", port=5353, slug="mdns",             runner="probe", probe="_nsa_mdns.py"),
}

SCANS = {}            # scan_id -> {module_id, name, slug, hosts:[{ip,port,status,command,output,findings}]}
SCAN_LOCK = threading.Lock()


# ── target parsing (mirrors parse_target) ──────────────────────────────────────
def parse_targets(text):
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        ip = parts[0]
        if not TARGET_RE.match(ip):
            continue
        port = None
        if len(parts) >= 3 and parts[1] == "-" and parts[2].isdigit():
            port = parts[2]
        elif len(parts) >= 3 and parts[1].lower() == "port" and parts[2].isdigit():
            port = parts[2]
        elif len(parts) >= 2 and parts[1].isdigit():
            port = parts[1]
        out.append((ip, port))
    return out


def valid_port(p):
    try:
        n = int(p)
        return 1 <= n <= 65535
    except Exception:
        return False


# ── per-module command builders ────────────────────────────────────────────────
def build_cmd(mid, ip, port):
    """Return argv for 'cmd' modules 1-6. Ports for nmap-based checks are fixed,
    exactly as in the original script."""
    if mid == 1: return ["nmap","-sU","-p","123","-n","-Pn","--script","ntp-monlist", ip]
    if mid == 2: return ["nmap","-sU","-p","123","--script","ntp-info", ip]
    if mid == 3: return ["snmp-check", ip, "-c","public"]
    if mid == 4: return ["nmap","--script","smb-security-mode.nse","-p","445", ip]
    if mid == 5: return ["nmap","--script","amqp-info","-p","5672", ip]
    if mid == 6: return ["timeout","3","redis-cli","-h",ip,"-p",str(port),"INFO"]
    return None


def classify_cmd(mid, rc, out):
    """Marker-based classification for modules 1-6. Returns (is_vuln, findings)."""
    if mid == 1:
        if "ntp-monlist:" in out: return True, ["NTP Monlist enabled - DoS amplification ~700x"]
    elif mid == 2:
        if "ntp-info:" in out: return True, ["NTP Mode 6 responsive - info leak/amplification"]
    elif mid == 3:
        if any(k in out for k in ("System information","Network interfaces","Software components","Storage information")):
            return True, ["SNMP public community accepted - full info exposed"]
    elif mid == 4:
        if "message_signing: disabled" in out: return True, ["SMB signing disabled - NTLM relay possible"]
    elif mid == 5:
        if "amqp-info:" in out: return True, ["AMQP responding without authentication"]
    elif mid == 6:
        if rc == 0: return True, ["Redis unauthenticated - full DB access"]
    return False, []


def classify_probe(out):
    """Line-key classification for probe modules 9-25 (mirrors run_scan case 9-25)."""
    findings, details = [], []
    is_vuln = False
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        key = line.split(":", 1)[0]
        if key in INFO_KEYS:
            details.append(line)
        else:
            findings.append(line)
            is_vuln = True
    return is_vuln, findings, details


def run_subprocess(argv):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=PER_TARGET_TIMEOUT)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "[timeout: exceeded %ds]" % PER_TARGET_TIMEOUT
    except FileNotFoundError:
        return 127, "[error: '%s' not found in PATH]" % argv[0]
    except Exception as e:
        return 1, "[error: %s]" % e


# ── run one target for one module ──────────────────────────────────────────────
def run_target(mid, ip, port):
    m = MODULES[mid]
    port = port or str(m["port"])
    if not valid_port(port):
        port = str(m["port"])
    runner = m["runner"]

    if runner == "cmd":
        argv = build_cmd(mid, ip, port)
        cmd_str = " ".join(shlex.quote(a) for a in argv)
        rc, out = run_subprocess(argv)
        is_vuln, findings = classify_cmd(mid, rc, out)
        detail_lines = []

    elif runner in ("ipmi", "smtp"):
        use_msf = shutil.which("msfconsole") is not None
        if runner == "ipmi":
            if use_msf:
                xcmd = ("use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS %s; "
                        "set RPORT %s; set VERBOSE true; run; exit" % (ip, port))
                argv = ["msfconsole","-q","-x", xcmd]
                cmd_str = " ".join(shlex.quote(a) for a in argv)
                rc, out = run_subprocess(argv)
                is_vuln = any("[+]" in l and "Hash found:" in l for l in out.splitlines())
                findings = [l.strip() for l in out.splitlines() if "[+]" in l and "Hash found:" in l]
                if is_vuln:
                    _append_file("ipmi_hashes.txt", "%s %s\n" % (ip, "\n".join(findings)))
            else:
                argv = ["python3", os.path.join(PROBE_DIR, "_nsa_ipmi.py"), ip, port]
                cmd_str = "python3 NSA/_nsa_ipmi.py %s %s" % (ip, port)
                rc, out = run_subprocess(argv)
                is_vuln = bool(out.strip())
                findings = [l for l in out.splitlines() if l.strip()]
                if is_vuln:
                    _append_file("ipmi_hashes.txt", out + ("\n" if not out.endswith("\n") else ""))
        else:  # smtp
            if use_msf:
                xcmd = ("use auxiliary/scanner/smtp/smtp_enum; set RHOSTS %s; "
                        "set RPORT %s; set VERBOSE true; run; exit" % (ip, port))
                argv = ["msfconsole","-q","-x", xcmd]
                cmd_str = " ".join(shlex.quote(a) for a in argv)
                rc, out = run_subprocess(argv)
                is_vuln = any("[+]" in l and "Users found:" in l for l in out.splitlines())
                findings = [l.strip() for l in out.splitlines() if "[+]" in l and "Users found:" in l]
            else:
                argv = ["python3", os.path.join(PROBE_DIR, "_nsa_smtp.py"), ip, port]
                cmd_str = "python3 NSA/_nsa_smtp.py %s %s" % (ip, port)
                rc, out = run_subprocess(argv)
                is_vuln = bool(out.strip())
                findings = [l for l in out.splitlines() if l.strip()]
            if is_vuln:
                _append_file("smtp_enum_details.txt", "HOST: %s Port %s\n%s\n\n" % (ip, port, out))
        detail_lines = []

    else:  # probe (9-25)
        argv = ["python3", os.path.join(PROBE_DIR, m["probe"]), ip, port]
        cmd_str = "python3 NSA/%s %s %s" % (m["probe"], ip, port)
        rc, out = run_subprocess(argv)
        is_vuln, findings, detail_lines = classify_probe(out)

    return dict(
        ip=ip, port=port,
        status="vuln" if is_vuln else "safe",
        command=cmd_str,
        output=out,
        findings=findings,
        details=detail_lines,
    )


def _append_file(name, text):
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(os.path.join(OUTPUT_DIR, name), "a", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass


# ── command preview for the module page (placeholder ip/port) ──────────────────
def cmd_preview(mid):
    m = MODULES[mid]
    ip, port = "<ip>", str(m["port"])
    if m["runner"] == "cmd":
        return " ".join(shlex.quote(a) if a not in ("<ip>",) else a for a in build_cmd(mid, ip, port))
    if m["runner"] == "ipmi":
        return ("msfconsole (if installed) auxiliary/scanner/ipmi/ipmi_dumphashes  "
                "— else:  python3 NSA/_nsa_ipmi.py <ip> %s" % port)
    if m["runner"] == "smtp":
        return ("msfconsole (if installed) auxiliary/scanner/smtp/smtp_enum  "
                "— else:  python3 NSA/_nsa_smtp.py <ip> %s" % port)
    return "python3 NSA/%s <ip> %s" % (m["probe"], port)


# ── scan driver (streams NDJSON) ───────────────────────────────────────────────
def run_scan_stream(mid, targets, workers, emit):
    m = MODULES[mid]
    total = len(targets)
    scan_id = uuid.uuid4().hex[:12]
    hosts = []
    emit({"t": "start", "total": total, "module": m["name"], "scan_id": scan_id,
          "cmd_preview": cmd_preview(mid)})
    done = 0
    lock = threading.Lock()

    def work(item):
        ip, port = item
        res = run_target(mid, ip, port)
        return res

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = [ex.submit(work, t) for t in targets]
        for fut in _as_completed(futs):
            res = fut.result()
            with lock:
                done += 1
                hosts.append(res)
                emit({"t": "host", "i": done, "total": total,
                      "ip": res["ip"], "port": res["port"], "status": res["status"],
                      "findings": res["findings"][:6]})

    vuln = [h for h in hosts if h["status"] == "vuln"]
    safe = [h for h in hosts if h["status"] == "safe"]
    with SCAN_LOCK:
        SCANS[scan_id] = dict(module_id=mid, name=m["name"], slug=m["slug"], hosts=hosts)
    emit({"t": "done", "scan_id": scan_id,
          "stats": {"overall": len(hosts), "vuln": len(vuln), "safe": len(safe)}})


def _as_completed(futs):
    from concurrent.futures import as_completed
    return as_completed(futs)


# ── saving buckets to per-host files ───────────────────────────────────────────
BUCKET_LABEL = {"overall": "all", "vuln": "vulnerable", "safe": "not_vulnerable"}


def save_bucket(scan_id, bucket):
    with SCAN_LOCK:
        scan = SCANS.get(scan_id)
    if not scan:
        raise KeyError("unknown scan")
    if bucket == "vuln":
        hosts = [h for h in scan["hosts"] if h["status"] == "vuln"]
    elif bucket == "safe":
        hosts = [h for h in scan["hosts"] if h["status"] == "safe"]
    else:
        hosts = scan["hosts"]

    folder = os.path.join(OUTPUT_DIR, "%s_%s" % (scan["slug"], BUCKET_LABEL[bucket]))
    os.makedirs(folder, exist_ok=True)
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    seen = {}
    for h in hosts:
        base = "%s Port %s" % (h["ip"], h["port"])
        n = seen.get(base, 0)
        seen[base] = n + 1
        fname = base + (".txt" if n == 0 else " (%d).txt" % n)
        status_txt = "VULNERABLE" if h["status"] == "vuln" else "NOT VULNERABLE"
        body = (
            "%s\n"
            "Target  : %s Port %s\n"
            "Status  : %s\n"
            "Scanned : %s\n"
            "Command : %s\n"
            "%s\n"
            "%s\n"
        ) % (scan["name"], h["ip"], h["port"], status_txt, ts, h["command"],
             "=" * 60, h["output"].rstrip("\n"))
        with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
            f.write(body)
    rel = os.path.relpath(folder, BASE_DIR)
    return rel, len(hosts)


# ── HTTP handler ───────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"     # close per request -> simple streaming

    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self._send(200, "text/html; charset=utf-8", INDEX_HTML)
        elif self.path == "/modules":
            data = [dict(id=i, name=m["name"], cat=m["cat"], port=m["port"],
                         slug=m["slug"], cmd=cmd_preview(i)) for i, m in sorted(MODULES.items())]
            self._send(200, "application/json", json.dumps(data))
        else:
            self._send(404, "text/plain", "not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            self._send(400, "text/plain", "bad json"); return

        if self.path == "/scan":
            self._stream_scan(payload)
        elif self.path == "/save":
            try:
                rel, count = save_bucket(payload["scan_id"], payload["bucket"])
                self._send(200, "application/json", json.dumps({"folder": rel, "count": count}))
            except KeyError:
                self._send(404, "application/json", json.dumps({"error": "unknown scan"}))
            except Exception as e:
                self._send(500, "application/json", json.dumps({"error": str(e)}))
        else:
            self._send(404, "text/plain", "not found")

    def _stream_scan(self, payload):
        try:
            mid = int(payload.get("module"))
            assert mid in MODULES
        except Exception:
            self._send(400, "text/plain", "bad module"); return
        targets = parse_targets(payload.get("targets", ""))
        workers = int(payload.get("workers", 10) or 10)
        if not targets:
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.end_headers()
            self.wfile.write((json.dumps({"t": "error", "msg": "no valid targets"}) + "\n").encode())
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.end_headers()

        lock = threading.Lock()
        def emit(obj):
            with lock:
                try:
                    self.wfile.write((json.dumps(obj) + "\n").encode("utf-8"))
                    self.wfile.flush()
                except Exception:
                    pass
        try:
            run_scan_stream(mid, targets, workers, emit)
        except Exception as e:
            emit({"t": "error", "msg": str(e)})


# ── front-end (single page, no dependencies) ───────────────────────────────────
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NSA Web</title>
<style>
:root{--bg:#0b0e14;--pan:#111722;--pan2:#0e1420;--bd:#1e2a3a;--fg:#c9d4e3;--mut:#6b7a90;
--grn:#35d07f;--red:#ff5c6c;--yel:#f6c453;--cyn:#49c5ff;--acc:#49c5ff;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:14px 20px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:12px;background:var(--pan2)}
header b{color:var(--cyn);font-size:16px;letter-spacing:.5px}
header .sub{color:var(--mut);font-size:12px}
.wrap{max-width:1100px;margin:0 auto;padding:20px}
.hide{display:none!important}
.cat{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:18px 0 8px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:8px}
.mod{background:var(--pan);border:1px solid var(--bd);border-radius:8px;padding:11px 13px;cursor:pointer;display:flex;gap:10px;align-items:center;transition:.12s}
.mod:hover{border-color:var(--acc);transform:translateY(-1px)}
.mod .id{color:var(--cyn);font-weight:700;min-width:26px}
.mod .nm{font-size:12.5px}
.mod .pt{margin-left:auto;color:var(--mut);font-size:11px}
.back{color:var(--cyn);cursor:pointer;font-size:12px;user-select:none}
.back:hover{text-decoration:underline}
h2{font-size:17px;margin:10px 0 4px}
.cmdbox{background:#060a10;border:1px solid var(--bd);border-left:3px solid var(--cyn);border-radius:6px;padding:10px 12px;color:var(--yel);font-size:12.5px;white-space:pre-wrap;word-break:break-all;margin:10px 0}
label{display:block;color:var(--mut);font-size:12px;margin:14px 0 6px}
textarea{width:100%;height:190px;background:#060a10;color:var(--fg);border:1px solid var(--bd);border-radius:6px;padding:10px;font:13px/1.5 ui-monospace,monospace;resize:vertical}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px}
button{background:var(--pan);color:var(--fg);border:1px solid var(--bd);border-radius:6px;padding:9px 16px;cursor:pointer;font:inherit;transition:.12s}
button:hover{border-color:var(--acc)}
button.run{background:var(--grn);color:#042014;border-color:var(--grn);font-weight:700}
button.run:hover{filter:brightness(1.08)}
button:disabled{opacity:.5;cursor:not-allowed}
.file{color:var(--mut);font-size:12px}
input[type=file]{color:var(--mut);font-size:12px}
.wk{width:60px;background:#060a10;color:var(--fg);border:1px solid var(--bd);border-radius:6px;padding:6px}
#term{background:#05080d;border:1px solid var(--bd);border-radius:8px;padding:12px;height:360px;overflow:auto;font-size:12.5px;white-space:pre-wrap;margin-top:14px}
#term .v{color:var(--red)} #term .s{color:var(--mut)} #term .h{color:var(--grn)}
#term .f{color:var(--yel);padding-left:22px}
.bar{height:6px;background:#0e1626;border-radius:4px;overflow:hidden;margin-top:12px}
.bar>i{display:block;height:100%;width:0;background:var(--cyn);transition:width .15s}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:16px}
.stat{background:var(--pan);border:1px solid var(--bd);border-radius:8px;padding:14px;text-align:center}
.stat .n{font-size:30px;font-weight:800}
.stat .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
.stat.ov{border-color:#2a3a52}.stat.ov .n{color:var(--cyn)}
.stat.vu{border-color:#3a2330}.stat.vu .n{color:var(--red)}
.stat.sa{border-color:#17321f}.stat.sa .n{color:var(--grn)}
.stat button{margin-top:10px;width:100%;font-size:12px;padding:7px}
.toast{margin-top:12px;color:var(--grn);font-size:12.5px;min-height:18px}
</style></head><body>
<header><b>NSA Web</b><span class="sub">Network Security Auditor &middot; localhost</span>
<span class="sub" id="where" style="margin-left:auto"></span></header>
<div class="wrap">

  <!-- MODULE LIST -->
  <section id="list"></section>

  <!-- MODULE DETAIL -->
  <section id="detail" class="hide">
    <div class="back" onclick="showList()">&larr; all modules</div>
    <h2><span id="dId" style="color:var(--cyn)"></span> <span id="dName"></span></h2>
    <div style="color:var(--mut);font-size:12px">Command to be executed</div>
    <div class="cmdbox" id="dCmd"></div>

    <label>Upload a target file &nbsp;<span class="file">(format: <code>x.x.x.x Port xx</code>, one per line)</span></label>
    <input type="file" id="file" accept=".txt,.lst,text/plain">
    <label>…or paste targets</label>
    <textarea id="targets" placeholder="192.168.1.10 Port 445&#10;10.0.0.5 Port 3389&#10;172.16.0.9"></textarea>

    <div class="row">
      <button class="run" id="runBtn" onclick="runScan()">▶ Run scan</button>
      <span class="file">workers</span><input class="wk" id="workers" type="number" min="1" max="64" value="10">
      <span class="file" id="count"></span>
    </div>

    <div class="bar"><i id="barFill"></i></div>
    <div id="term"></div>

    <div class="stats hide" id="stats">
      <div class="stat ov"><div class="n" id="sOv">0</div><div class="l">Overall</div>
        <button onclick="save('overall',this)">Save output</button></div>
      <div class="stat vu"><div class="n" id="sVu">0</div><div class="l">Vulnerable</div>
        <button onclick="save('vuln',this)">Save output</button></div>
      <div class="stat sa"><div class="n" id="sSa">0</div><div class="l">Not Vulnerable</div>
        <button onclick="save('safe',this)">Save output</button></div>
    </div>
    <div class="toast" id="toast"></div>
  </section>
</div>
<script>
let MODS=[], CUR=null, SCAN_ID=null;
const $=s=>document.querySelector(s);

fetch('/modules').then(r=>r.json()).then(d=>{MODS=d;renderList();});

function renderList(){
  const byCat={};
  MODS.forEach(m=>{(byCat[m.cat]=byCat[m.cat]||[]).push(m);});
  const order=["Network Services","Auth & Hashing","File Sharing","Remote Access","Databases","App / Middleware"];
  let h='';
  order.forEach(c=>{ if(!byCat[c])return;
    h+=`<div class="cat">${c}</div><div class="grid">`;
    byCat[c].forEach(m=>{ h+=`<div class="mod" onclick="openMod(${m.id})">
      <span class="id">${m.id}</span><span class="nm">${esc(m.name)}</span><span class="pt">:${m.port}</span></div>`;});
    h+='</div>';
  });
  $('#list').innerHTML=h;
}
function openMod(id){
  CUR=MODS.find(m=>m.id===id); SCAN_ID=null;
  $('#dId').textContent='['+CUR.id+']';
  $('#dName').textContent=CUR.name;
  $('#dCmd').textContent=CUR.cmd;
  $('#targets').value=''; $('#file').value='';
  $('#term').innerHTML=''; $('#stats').classList.add('hide');
  $('#toast').textContent=''; $('#barFill').style.width='0';
  $('#count').textContent='';
  $('#list').classList.add('hide'); $('#detail').classList.remove('hide');
  window.scrollTo(0,0);
}
function showList(){ $('#detail').classList.add('hide'); $('#list').classList.remove('hide'); }

$('#file').addEventListener('change',e=>{
  const f=e.target.files[0]; if(!f)return;
  const r=new FileReader(); r.onload=()=>{ $('#targets').value=r.result; countTargets(); }; r.readAsText(f);
});
$('#targets').addEventListener('input',countTargets);
function countTargets(){
  const n=$('#targets').value.split('\n').filter(l=>/^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(l)).length;
  $('#count').textContent=n?`${n} target(s)`:'';
}

function termLine(cls,txt){ const d=document.createElement('div'); if(cls)d.className=cls; d.textContent=txt;
  const t=$('#term'); t.appendChild(d); t.scrollTop=t.scrollHeight; }

async function runScan(){
  const targets=$('#targets').value.trim();
  if(!targets){ $('#toast').textContent='Paste or upload targets first.'; return; }
  $('#runBtn').disabled=true; $('#term').innerHTML=''; $('#stats').classList.add('hide');
  $('#toast').textContent=''; $('#barFill').style.width='0';
  termLine('s','$ scanning — module '+CUR.id+' ('+CUR.name+')');
  let total=0,done=0;
  try{
    const resp=await fetch('/scan',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({module:CUR.id,targets:targets,workers:+$('#workers').value||10})});
    const reader=resp.body.getReader(); const dec=new TextDecoder(); let buf='';
    while(true){
      const {value,done:rd}=await reader.read(); if(rd)break;
      buf+=dec.decode(value,{stream:true}); let nl;
      while((nl=buf.indexOf('\n'))>=0){
        const line=buf.slice(0,nl); buf=buf.slice(nl+1); if(!line.trim())continue;
        const ev=JSON.parse(line); handle(ev);
      }
    }
  }catch(e){ termLine('v','[stream error] '+e); }
  $('#runBtn').disabled=false;

  function handle(ev){
    if(ev.t==='start'){ total=ev.total; termLine('s','$ '+total+' targets, command: '+ev.cmd_preview); }
    else if(ev.t==='host'){
      done=ev.i; $('#barFill').style.width=(100*done/total)+'%';
      if(ev.status==='vuln'){
        termLine('v','['+ev.i+'/'+ev.total+'] '+ev.ip+':'+ev.port+'  ▶ VULNERABLE');
        (ev.findings||[]).forEach(f=>termLine('f','→ '+f));
      } else {
        termLine('s','['+ev.i+'/'+ev.total+'] '+ev.ip+':'+ev.port+'  ✓ not vulnerable');
      }
    }
    else if(ev.t==='done'){
      SCAN_ID=ev.scan_id;
      $('#sOv').textContent=ev.stats.overall; $('#sVu').textContent=ev.stats.vuln; $('#sSa').textContent=ev.stats.safe;
      $('#stats').classList.remove('hide');
      termLine('h','$ done — '+ev.stats.overall+' scanned, '+ev.stats.vuln+' vulnerable, '+ev.stats.safe+' not vulnerable');
    }
    else if(ev.t==='error'){ termLine('v','[error] '+ev.msg); }
  }
}

async function save(bucket,btn){
  if(!SCAN_ID){ $('#toast').textContent='Run a scan first.'; return; }
  btn.disabled=true; const old=btn.textContent; btn.textContent='saving…';
  try{
    const r=await fetch('/save',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({scan_id:SCAN_ID,bucket:bucket})});
    const d=await r.json();
    if(d.error){ $('#toast').textContent='Error: '+d.error; }
    else{ $('#toast').textContent='✓ Saved '+d.count+' file(s) → '+d.folder+'/'; }
  }catch(e){ $('#toast').textContent='Save failed: '+e; }
  btn.disabled=false; btn.textContent=old;
}
function esc(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
</script></body></html>
"""


# ── startup ────────────────────────────────────────────────────────────────────
def check_probes():
    missing = [m["probe"] for m in MODULES.values()
               if m["runner"] == "probe" and not os.path.exists(os.path.join(PROBE_DIR, m["probe"]))]
    for extra in ("_nsa_ipmi.py", "_nsa_smtp.py"):
        if not os.path.exists(os.path.join(PROBE_DIR, extra)):
            missing.append(extra)
    return missing


def main():
    ap = argparse.ArgumentParser(description="NSA Web — local web UI for the Network Security Auditor")
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    missing = check_probes()
    if missing:
        print("[!] Missing probe files in %s:" % PROBE_DIR)
        for m in missing:
            print("    - %s" % m)
        print("[!] Make sure the NSA/ folder (with _nsa_*.py) sits next to nsa_web.py.")
        sys.exit(1)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("[!] Refusing to bind to a non-localhost address (%s)." % args.host)
        print("    This page executes scan commands; localhost only. Edit the source if you truly mean it.")
        sys.exit(1)

    url = "http://%s:%d/" % (args.host, args.port)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("  NSA Web  →  %s" % url)
    print("  Output folder: %s" % OUTPUT_DIR)
    print("  (Ctrl-C to stop)")
    if not args.no_browser:
        threading.Thread(target=lambda: (time.sleep(0.7), _open(url)), daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped.")


def _open(url):
    try:
        webbrowser.open(url)
    except Exception:
        pass


if __name__ == "__main__":
    main()
