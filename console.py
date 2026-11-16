#!/usr/bin/env python3
# ============================================================================
# ARGUS — one local web console over two engines, Nessus-style.
#   • Subnet recon  (SweepNinja: ping sweep → parallel nmap → classify →
#                    searchsploit → HTTP screenshots)  — logic unchanged
#   • Module scan   (NSA: the 25 service/CVE modules)                — unchanged
#   • In-app scheduler with calendar date/time + timezone
#   • Results browser (renders SweepNinja dashboard.html inline) + screenshot gallery
#
# Dependency-free: Python 3 standard library + vanilla JS. Localhost only.
#   python3 console.py            → http://127.0.0.1:8800/
# ============================================================================

import os, sys, re, json, time, uuid, html, shlex, shutil, signal, threading, argparse, subprocess, webbrowser, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

try:
    from zoneinfo import ZoneInfo, available_timezones
    _HAVE_TZ = True
except Exception:
    _HAVE_TZ = False

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
ENGINE_DIR = os.path.join(BASE_DIR, "engine")
WS_ROOT    = os.path.join(BASE_DIR, "workspaces")
MODRES_DIR = os.path.join(BASE_DIR, "module_results")   # SHARED across all module scans
SCHED_FILE = os.path.join(BASE_DIR, "schedules.json")
UI_FILE    = os.path.join(BASE_DIR, "ui.html")

sys.path.insert(0, BASE_DIR)
import nsa_web   # reuse the NSA module engine (MODULES, run_target, parse_targets, cmd_preview)

os.makedirs(WS_ROOT, exist_ok=True)

JOBS = {}            # id -> job dict
JOBS_LOCK = threading.Lock()
SCHEDULES = {}       # id -> schedule dict
SCHED_LOCK = threading.Lock()


# ── small helpers ────────────────────────────────────────────────────────────
def now_iso():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sanitize_subnet(s):
    return re.sub(r"\s+", "", s).replace("/", "-")

def cidr_slot_cost(subnet):
    m = re.search(r"/(\d+)", subnet)
    prefix = int(m.group(1)) if m else 24
    if prefix <= 8:  return 8
    if prefix <= 12: return 6
    if prefix <= 16: return 4
    if prefix <= 20: return 2
    return 1

def machine_resources():
    """Detect CPU/RAM and derive safe concurrency so we never overload the box."""
    try:
        cores = os.cpu_count() or 2
    except Exception:
        cores = 2
    ram_gb = 4
    ram_avail_gb = None
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    ram_gb = max(1, int(line.split()[1]) // 1048576)
                elif line.startswith("MemAvailable"):
                    ram_avail_gb = max(1, int(line.split()[1]) // 1048576)
    except Exception:
        pass
    budget_gb = ram_avail_gb if ram_avail_gb else ram_gb
    # nmap subnet slots (CIDR-weighted pool): cores*ram/4, capped 1..16
    slots = max(1, min(16, (cores * ram_gb) // 4))
    # module-scan workers: mostly network-bound, but a probe may spawn nmap/mysql,
    # so budget ~200 MB of available RAM each and ~2 per core.
    workers = max(2, min(32, cores * 2))
    workers = min(workers, max(2, (budget_gb * 1024) // 200))
    # headless-chrome screenshots are RAM-heavy (~300 MB each): ~1 per GB, capped by cores and 8
    snap = max(2, min(cores, max(2, budget_gb), 8))
    return {"cpu_cores": cores, "ram_gb": ram_gb,
            "ram_available_gb": ram_avail_gb if ram_avail_gb else ram_gb,
            "recommended_slots": int(slots),
            "recommended_workers": int(workers),
            "screenshot_threads": int(snap)}

def detect_resources():
    return machine_resources()["recommended_slots"]

def _read_cpu_sample():
    with open("/proc/stat") as f:
        parts = f.readline().split()[1:]
    vals = [int(x) for x in parts[:8]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)   # idle + iowait
    return idle, sum(vals)

def system_stats():
    """Live CPU %, RAM usage and load average (stdlib only, Linux /proc)."""
    cpu = 0.0
    try:
        i1, t1 = _read_cpu_sample(); time.sleep(0.12); i2, t2 = _read_cpu_sample()
        dt = t2 - t1; di = i2 - i1
        if dt > 0:
            cpu = max(0.0, min(100.0, 100.0 * (1 - di / dt)))
    except Exception:
        pass
    mem_total = mem_avail = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"): mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable"): mem_avail = int(line.split()[1])
    except Exception:
        pass
    mem_used = max(0, mem_total - mem_avail)
    try: load1 = os.getloadavg()[0]
    except Exception: load1 = 0.0
    cores = (os.cpu_count() or 1)
    return {"cpu_pct": round(cpu), "cores": cores,
            "mem_pct": round(100 * mem_used / mem_total) if mem_total else 0,
            "mem_used_gb": round(mem_used / 1048576, 1),
            "mem_total_gb": round(mem_total / 1048576, 1),
            "load1": round(load1, 2),
            "load_pct": round(min(100.0, 100.0 * load1 / cores)) if cores else 0,
            "active_scans": _running_job_count()}

def _running_job_count():
    with JOBS_LOCK:
        return sum(1 for j in JOBS.values()
                   if j.get("status") in ("running", "paused", "queued"))

def active_scan_count():
    """Number of scans currently occupying machine resources."""
    with JOBS_LOCK:
        return max(1, sum(1 for j in JOBS.values()
                          if j.get("status") in ("running", "paused", "queued")))

def shared(base):
    """Divide a resource budget across the concurrently-running scans."""
    return max(1, int(base) // active_scan_count())

# CLI tools the project can invoke, with purpose + how critical they are.
TOOLS_USED = [
    ("python3",     "core — runs probes & the recon engine", "required"),
    ("nmap",        "port scanning / NSE scripts (recon + modules)", "required"),
    ("searchsploit","exploit matching for discovered components (exploitdb)", "recon"),
    ("snmp-check",  "SNMP default-community module", "module"),
    ("redis-cli",   "Redis unauth module", "module"),
    ("smbclient",   "SMB / LANMAN null-session modules", "module"),
    ("smbmap",      "SMB share enumeration", "module"),
    ("showmount",   "NFS exports module", "module"),
    ("mount",       "NFS mount test", "module"),
    ("mysql",       "MySQL weak-cred module", "module"),
    ("nmblookup",   "LANMAN NetBIOS module", "module"),
    ("rpcclient",   "SMB RPC enumeration", "module"),
    ("rpcdump.py",  "PrintNightmare spooler check (impacket)", "module"),
    ("ncrack",      "RDP credential brute (optional)", "optional"),
    ("dig",         "DNS checks (optional)", "optional"),
    ("msfconsole",  "IPMI/SMTP via Metasploit (optional; falls back to probe)", "optional"),
    ("eyewitness",  "HTTP screenshots", "recon"),
    ("gowitness",   "HTTP screenshots", "recon"),
]

def sort_subnets_by_cidr(subnets):
    def pref(s):
        m = re.search(r"/(\d+)", s); return int(m.group(1)) if m else 24
    return sorted([s.strip() for s in subnets if s.strip()], key=pref, reverse=True)

def safe_join(root, rel):
    """Join rel to root, refusing path traversal. Returns abspath or None."""
    rel = unquote(rel).lstrip("/")
    full = os.path.normpath(os.path.join(root, rel))
    if full != root and not full.startswith(root + os.sep):
        return None
    return full


# ── job model ────────────────────────────────────────────────────────────────
class StopScan(Exception):
    """Raised inside a running job when the user requests Stop."""

def new_job(jtype, name, config, ws_slug=None):
    jid = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    # workspace folder: named by subnet for recon, else the job id
    if ws_slug:
        base = re.sub(r"[^\w.\-]", "_", ws_slug).strip("_") or jid
        ws = os.path.join(WS_ROOT, base)
        if os.path.exists(ws):                      # same subnet scanned before → add time suffix
            ws = os.path.join(WS_ROOT, "%s_%s" % (base, time.strftime("%H%M%S")))
            if os.path.exists(ws):
                ws = os.path.join(WS_ROOT, "%s_%s" % (base, uuid.uuid4().hex[:4]))
    else:
        ws = os.path.join(WS_ROOT, jid)
    os.makedirs(ws, exist_ok=True)
    job = dict(id=jid, type=jtype, name=name or jtype, status="queued",
               created=now_iso(), config=config, workspace=ws, trashed=False,
               log=[], stats={}, _v=0,
               control={"pause": False, "stop": False},
               progress=[], started_at=None, ended_at=None,
               _procs=set(), _plock=threading.Lock())
    with JOBS_LOCK:
        JOBS[jid] = job
    write_meta(job)
    return job

def write_meta(job):
    meta = {k: job[k] for k in ("id", "type", "name", "status", "created", "config", "stats")}
    meta["trashed"] = job.get("trashed", False)
    meta["progress"] = job.get("progress", [])
    meta["started_at"] = job.get("started_at")
    meta["ended_at"] = job.get("ended_at")
    try:
        with open(os.path.join(job["workspace"], "meta.json"), "w") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass

# ── progress + control ───────────────────────────────────────────────────────
def prog_add(job, name, total):
    """Begin a stage; returns its index."""
    entry = {"name": name, "status": "running", "done": 0, "total": max(0, int(total)),
             "started": time.time(), "ended": None}
    with JOBS_LOCK:
        job["progress"].append(entry)
        idx = len(job["progress"]) - 1
        job["_v"] += 1
    return idx

def prog_step(job, idx, n=1):
    with JOBS_LOCK:
        if 0 <= idx < len(job["progress"]):
            job["progress"][idx]["done"] += n
            job["_v"] += 1

def prog_set_total(job, idx, total):
    with JOBS_LOCK:
        if 0 <= idx < len(job["progress"]):
            job["progress"][idx]["total"] = max(0, int(total))
            job["_v"] += 1

def prog_done(job, idx, status="done"):
    with JOBS_LOCK:
        if 0 <= idx < len(job["progress"]):
            e = job["progress"][idx]
            e["status"] = status
            e["ended"] = time.time()
            if status == "done" and e["total"]:
                e["done"] = e["total"]
            job["_v"] += 1

def reg_proc(job, p):
    with job["_plock"]:
        job["_procs"].add(p)

def unreg_proc(job, p):
    with job["_plock"]:
        job["_procs"].discard(p)

def _sig_proc(p, sig):
    """Signal the process group (so grandchildren like chrome die too), then the proc."""
    try:
        os.killpg(os.getpgid(p.pid), sig)
    except Exception:
        try:
            p.terminate() if sig == signal.SIGTERM else p.kill()
        except Exception:
            pass

def kill_job_procs(job):
    with job["_plock"]:
        procs = list(job["_procs"])
    for p in procs:
        _sig_proc(p, signal.SIGTERM)
    time.sleep(0.4)
    for p in procs:
        try:
            if p.poll() is None:
                _sig_proc(p, signal.SIGKILL)
        except Exception:
            pass

def gate(job):
    """Checkpoint between work units: block while paused, raise on stop."""
    paused_announced = False
    while job["control"]["pause"] and not job["control"]["stop"]:
        if not paused_announced:
            set_status(job, "paused"); emit(job, "⏸ paused"); paused_announced = True
        time.sleep(0.4)
    if job["control"]["stop"]:
        raise StopScan()
    if paused_announced:
        set_status(job, "running"); emit(job, "▶ resumed")

def emit(job, line):
    with JOBS_LOCK:
        job["log"].append(line)
        job["_v"] += 1
    try:
        with open(os.path.join(job["workspace"], "scan.log"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def set_status(job, status):
    job["status"] = status
    write_meta(job)


def load_existing_workspaces():
    if not os.path.isdir(WS_ROOT):
        return
    for jid in sorted(os.listdir(WS_ROOT)):
        meta_p = os.path.join(WS_ROOT, jid, "meta.json")
        if not os.path.isfile(meta_p):
            continue
        try:
            with open(meta_p) as f:
                meta = json.load(f)
        except Exception:
            continue
        if meta.get("id") in JOBS:
            continue
        meta.update(workspace=os.path.join(WS_ROOT, jid), log=[], _v=0,
                    control={"pause": False, "stop": False}, _procs=set(),
                    _plock=threading.Lock())
        meta.setdefault("status", "done")
        meta.setdefault("trashed", False)
        with JOBS_LOCK:
            JOBS[meta["id"]] = meta


# ── subprocess helper ────────────────────────────────────────────────────────
def run(cmd, timeout=None, cwd=None, job=None):
    """Run argv list, return (rc, combined_output). When `job` is given the process
    is registered so a Stop request can terminate it mid-run (interruptible)."""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, cwd=cwd, start_new_session=True)
    except FileNotFoundError:
        return 127, "[not found: %s]" % (cmd[0] if cmd else "?")
    except Exception as e:
        return 1, "[error: %s]" % e
    if job is not None:
        reg_proc(job, p)
    try:
        out, err = p.communicate(timeout=timeout)
        return p.returncode, (out or "") + (err or "")
    except subprocess.TimeoutExpired:
        try:
            p.kill(); out, err = p.communicate()
        except Exception:
            out, err = "", ""
        return 124, (out or "") + (err or "") + "\n[timeout]"
    except Exception as e:
        return 1, "[error: %s]" % e
    finally:
        if job is not None:
            unreg_proc(job, p)

def have(binname):
    return shutil.which(binname) is not None


# ── RECON stages (commands identical to SweepNinja) ──────────────────────────
def stage_ping_sweep(job, subnets):
    emit(job, "=== PING SWEEP ===")
    pidx = prog_add(job, "Ping sweep", len(subnets))
    out = os.path.join(job["workspace"], "ping_sweep.txt")
    open(out, "w").close()
    total = len(subnets)
    for i, subnet in enumerate(subnets, 1):
        gate(job)
        emit(job, "[%d/%d] ping sweep %s ..." % (i, total, subnet))
        rc, res = run(["nmap", "-sn", subnet], timeout=1800, job=job)
        m = re.findall(r"(\d+)(?= IP addresses)", res)
        total_ips = m[-1] if m else "0"
        hosts_up = len(re.findall(r"Host is up", res))
        with open(out, "a") as f:
            f.write("%s  %s IP addresses  %d host(s) up\n" % (subnet, total_ips, hosts_up))
        emit(job, "      %s → %s IPs, %d up" % (subnet, total_ips, hosts_up))
        prog_step(job, pidx)
    prog_done(job, pidx)
    emit(job, "ping sweep saved → ping_sweep.txt")

def stage_nmap(job, subnets):
    emit(job, "=== NMAP SCAN (parallel, CIDR-weighted) ===")
    out_dir = os.path.join(job["workspace"], "nmap_scans")
    os.makedirs(out_dir, exist_ok=True)
    base_slots = detect_resources()
    max_slots = shared(base_slots)      # shared across concurrent scans; re-checked each loop
    ordered = sort_subnets_by_cidr(subnets)
    total = len(ordered)
    nidx = prog_add(job, "Nmap scan", total)
    emit(job, "resources: %d slot(s) (of %d, shared across %d scan[s]) | %d subnet(s)"
         % (max_slots, base_slots, active_scan_count(), total))
    active = {}      # Popen -> (subnet, cost, start)
    used = 0; qi = 0; done = 0
    while qi < len(ordered) or active:
        # reflect pause/resume (new launches are gated below; in-flight scans finish)
        if job["control"]["pause"] and job["status"] == "running":
            set_status(job, "paused"); emit(job, "⏸ paused (finishing in-flight subnets)")
        elif not job["control"]["pause"] and job["status"] == "paused":
            set_status(job, "running"); emit(job, "▶ resumed")
        if job["control"]["stop"]:
            for p in list(active):
                _sig_proc(p, signal.SIGTERM)
                unreg_proc(job, p)
            raise StopScan()
        max_slots = shared(base_slots)   # adapt live if another scan starts/stops
        for p in list(active):
            if p.poll() is not None:
                subnet, cost, st = active.pop(p)
                unreg_proc(job, p)
                used -= cost; done += 1
                prog_step(job, nidx)
                emit(job, "[%d/%d] ✔ %s done in %ds" % (done, total, subnet, int(time.time() - st)))
        # only launch new work when not paused
        while qi < len(ordered) and not job["control"]["pause"]:
            subnet = ordered[qi]
            cost = cidr_slot_cost(subnet)
            if used + cost > max_slots and active:
                break
            xml = os.path.join(out_dir, sanitize_subnet(subnet) + ".xml")
            try:
                p = subprocess.Popen(
                    ["nmap", "-T4", "-A", "-p-", "--min-rate", "1000",
                     "--max-retries", "2", "-oX", xml, subnet],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            except FileNotFoundError:
                emit(job, "[error] nmap not found in PATH"); prog_done(job, nidx, "error"); return
            reg_proc(job, p)
            active[p] = (subnet, cost, time.time()); used += cost; qi += 1
            emit(job, "▶ launch %s (cost %d) [slots %d/%d]" % (subnet, cost, used, max_slots))
        time.sleep(1)
    prog_done(job, nidx)
    xmls = len([x for x in os.listdir(out_dir) if x.endswith(".xml")])
    emit(job, "nmap done → %d XML file(s) in nmap_scans/" % xmls)

def stage_classify(job, track=True):
    emit(job, "=== CLASSIFICATION ===")
    cidx = prog_add(job, "Classification", 1) if track else -1
    ws = job["workspace"]
    nmap_dir = os.path.join(ws, "nmap_scans")
    class_dir = os.path.join(ws, "Classification")
    if not os.path.isdir(nmap_dir) or not any(f.endswith(".xml") for f in os.listdir(nmap_dir)):
        emit(job, "[skip] no nmap XMLs to classify")
        if track: prog_done(job, cidx, "skipped")
        return False
    os.makedirs(class_dir, exist_ok=True)
    tmp_json = os.path.join(ws, ".parsed.json")
    rc, parsed = run(["python3", "-I", os.path.join(ENGINE_DIR, "sn_parse_xmls.py"), nmap_dir], job=job)
    with open(tmp_json, "w") as f:
        f.write(parsed)
    if not parsed.strip() or parsed.strip() == "[]":
        emit(job, "[info] no open ports found in XMLs")
        if track: prog_done(job, cidx, "skipped")
        return False
    rc, out = run(["python3", "-I", os.path.join(ENGINE_DIR, "sn_classify.py"), tmp_json, class_dir], job=job)
    for ln in out.splitlines():
        if ln.strip():
            emit(job, ln.rstrip())
    emit(job, "classification saved → Classification/")
    if track: prog_done(job, cidx)
    return True

def stage_searchsploit(job):
    emit(job, "=== SEARCHSPLOIT ===")
    sidx = prog_add(job, "Searchsploit", 1)
    ws = job["workspace"]
    class_dir = os.path.join(ws, "Classification")
    cache = os.path.join(class_dir, ".components_cache.json")
    out_file = os.path.join(class_dir, "searchsploit.txt")
    if not have("searchsploit"):
        emit(job, "[skip] searchsploit not installed (apt install exploitdb)"); prog_done(job, sidx, "skipped"); return
    if not os.path.isfile(cache):
        emit(job, "[skip] no component cache — run classification first"); prog_done(job, sidx, "skipped"); return
    tmp_tsv = os.path.join(ws, ".comp.tsv")
    run(["python3", "-I", os.path.join(ENGINE_DIR, "sn_comp_tsv.py"), cache, tmp_tsv], job=job)
    with open(out_file, "w") as f:
        f.write("================================================================\n")
        f.write("  SEARCHSPLOIT RESULTS  —  SweepNinja\n")
        f.write("================================================================\n")
    try:
        rows = [l.rstrip("\n").split("\t") for l in open(tmp_tsv) if l.strip()]
    except Exception:
        rows = []
    total = len(rows); hits = 0
    prog_set_total(job, sidx, total or 1)
    for idx, parts in enumerate(rows, 1):
        gate(job)
        product = parts[0] if len(parts) > 0 else ""
        version = parts[1] if len(parts) > 1 else ""
        ips = parts[2] if len(parts) > 2 else ""
        query = ("%s %s" % (product, version)).strip() if version else product
        emit(job, "[%d/%d] searchsploit %s" % (idx, total, query))
        prog_step(job, sidx)
        rc, result = run(["searchsploit", "--colour=false", query], timeout=60, job=job)
        if "No Results Found" in result and version:
            query = product
            rc, result = run(["searchsploit", "--colour=false", product], timeout=60, job=job)
        has = ("Exploit Title" in result) and ("No Results Found" not in result)
        if has:
            hits += 1
        with open(out_file, "a") as f:
            f.write("\n◈ Searching for: %s\n" % query)
            if ips:
                f.write("  Seen on  : %s\n" % ips)
            f.write("\n")
            if has:
                f.write(result)
            else:
                f.write("  Exploit Title                                                    |  Path\n")
                f.write("  -----------------------------------------------------------------|---------\n")
                f.write("  No Results Found\n\n  Shellcodes: No Results\n")
            f.write("\n")
            f.write("_" * 80 + "\n")
    emit(job, "searchsploit done (%d/%d had results) → Classification/searchsploit.txt" % (hits, total))
    prog_done(job, sidx)
    # Re-classify so the dashboard embeds the exploit results (enrichment, same engine)
    emit(job, "re-building dashboard with exploit data ...")
    stage_classify(job, track=False)

def find_chrome():
    for b in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
              "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome",
              "/snap/bin/chromium"):
        r = shutil.which(b)
        if r: return r
        if os.path.isfile(b) and os.access(b, os.X_OK): return b
    return None

def find_aquatone():
    for p in ("aquatone", "/usr/local/bin/aquatone",
              os.path.expanduser("~/go/bin/aquatone"), "/root/go/bin/aquatone", "/opt/aquatone"):
        r = shutil.which(p)
        if r: return r
        if os.path.isfile(p) and os.access(p, os.X_OK): return p
    return None

def available_snap_tools():
    tools = []
    if have("eyewitness"): tools.append("eyewitness")
    if find_aquatone() and find_chrome(): tools.append("aquatone")
    if have("gowitness"): tools.append("gowitness")
    return tools

def stage_snaps(job, tool):
    emit(job, "=== HTTP SNAPS ===")
    ws = job["workspace"]
    http_file = os.path.join(ws, "Classification", "http.txt")
    snaps_dir = os.path.join(ws, "HTTP_Snaps")
    gidx = prog_add(job, "Screenshots", 1)
    if not os.path.isfile(http_file):
        emit(job, "[skip] no http.txt — run classification first"); prog_done(job, gidx, "skipped"); return
    urls = [re.sub(r"\s", "", l) for l in open(http_file) if re.search(r"https?://", l)]
    if not urls:
        emit(job, "[skip] no HTTP/HTTPS URLs found"); prog_done(job, gidx, "skipped"); return
    prog_set_total(job, gidx, len(urls))
    job["_snap_prog"] = gidx
    avail = available_snap_tools()
    if not avail:
        emit(job, "[skip] no screenshot tool available (eyewitness/aquatone/gowitness). URLs ready at Classification/http.txt")
        prog_done(job, gidx, "skipped"); return
    # Build the try-order: requested tool first, then the rest as fallbacks.
    if tool in (None, "", "auto") or tool not in avail:
        order = avail[:]
    else:
        order = [tool] + [t for t in avail if t != tool]
    os.makedirs(snaps_dir, exist_ok=True)
    tmp_urls = os.path.join(ws, ".urls.txt")
    with open(tmp_urls, "w") as f:
        f.write("\n".join(urls) + "\n")
    snap_threads = shared(machine_resources()["screenshot_threads"])
    emit(job, "%d URL(s) to screenshot. Tool order: %s (%d thread[s], shared across %d scan[s])"
         % (len(urls), " → ".join(order), snap_threads, active_scan_count()))

    done_tool, count = None, 0
    for t in order:
        emit(job, "▶ trying %s ..." % t)
        c = _run_snap_tool(job, t, tmp_urls, len(urls), snaps_dir, snap_threads)
        if c > 0:
            done_tool, count = t, c
            emit(job, "✔ %s produced %d screenshot(s)" % (t, c))
            break
        emit(job, "⚠ %s produced 0 screenshots — falling back to next tool" % t)
    if not done_tool:
        emit(job, "[warn] all screenshot tools failed (0 images). Check tool logs under HTTP_Snaps/.")
        prog_done(job, gidx, "error")
        return
    prog_done(job, gidx)
    # Build a unified, tool-agnostic screenshot report index.
    try:
        idx = build_snap_index(ws)
        with open(os.path.join(snaps_dir, "index.json"), "w") as f:
            json.dump(idx, f)
        emit(job, "screenshot report ready: %d image(s) across %d host(s)"
             % (idx["summary"]["total"], idx["summary"]["hosts"]))
    except Exception as e:
        emit(job, "[note] screenshot report index skipped: %s" % e)


def _run_snap_tool(job, tool, tmp_urls, n_urls, snaps_dir, snap_threads):
    """Run one screenshot tool; return the number of PNGs it produced."""
    if tool == "eyewitness":
        ew = os.path.join(snaps_dir, "eyewitness"); os.makedirs(ew, exist_ok=True)
        try:
            p = subprocess.Popen(["eyewitness", "--web", "-f", tmp_urls, "-d", ew,
                                  "--no-prompt", "--threads", str(snap_threads), "--timeout", "15"],
                                 stdout=open(os.path.join(ew, "eyewitness.log"), "w"), stderr=subprocess.STDOUT, start_new_session=True)
        except Exception as e:
            emit(job, "   eyewitness failed to start: %s" % e); return 0
        _watch_png(job, ew, n_urls, p)
        return _count_png(ew)
    if tool == "aquatone":
        aq = os.path.join(snaps_dir, "aquatone"); os.makedirs(aq, exist_ok=True)
        shutil.copy(tmp_urls, os.path.join(aq, "http.txt"))
        chrome = find_chrome(); aqbin = find_aquatone()
        if not aqbin or not chrome:
            emit(job, "   aquatone/chromium not found"); return 0
        aq_threads = max(2, min(snap_threads, 4))   # chrome is heavy; keep aquatone modest
        env = dict(os.environ, CHROMIUM_PATH=chrome)
        try:
            p = subprocess.Popen("cat http.txt | %s -chrome-path %s -out . -threads %d "
                                 "-scan-timeout 30000 -screenshot-timeout 30000"
                                 % (shlex.quote(aqbin), shlex.quote(chrome), aq_threads),
                                 shell=True, cwd=aq,
                                 stdout=open(os.path.join(aq, "aquatone.log"), "w"),
                                 stderr=subprocess.STDOUT, env=env, start_new_session=True)
        except Exception as e:
            emit(job, "   aquatone failed to start: %s" % e); return 0
        _watch_png(job, os.path.join(aq, "screenshots"), n_urls, p)
        return _count_png(os.path.join(aq, "screenshots"))
    if tool == "gowitness":
        gw = os.path.join(snaps_dir, "gowitness"); os.makedirs(gw, exist_ok=True)
        try:
            p = subprocess.Popen(["gowitness", "file", "-f", tmp_urls,
                                  "--screenshot-path", gw, "--threads", str(snap_threads), "--timeout", "10"],
                                 stdout=open(os.path.join(gw, "gowitness.log"), "w"), stderr=subprocess.STDOUT, start_new_session=True)
        except Exception as e:
            emit(job, "   gowitness failed to start: %s" % e); return 0
        _watch_png(job, gw, n_urls, p)
        return _count_png(gw)
    return 0

def _count_png(d):
    n = 0
    if os.path.isdir(d):
        for root, _, files in os.walk(d):
            n += sum(1 for f in files if f.endswith(".png"))
    return n

def _watch_png(job, watch_dir, total, p):
    last = -1
    gidx = job.get("_snap_prog", -1)
    while p.poll() is None:
        n = _count_png(watch_dir)
        if n != last:
            emit(job, "   screenshots: %d/%d" % (n, total)); last = n
            if gidx >= 0:
                with JOBS_LOCK:
                    if 0 <= gidx < len(job["progress"]):
                        job["progress"][gidx]["done"] = min(n, total); job["_v"] += 1
        time.sleep(2)
    emit(job, "   screenshots: %d/%d (complete)" % (_count_png(watch_dir), total))


# ── unified, tool-agnostic screenshot report ─────────────────────────────────
def _recover_ip(fname):
    """Pull an IPv4 out of a screenshot filename regardless of separator (. _ -)."""
    m = re.search(r"(\d{1,3})[._-](\d{1,3})[._-](\d{1,3})[._-](\d{1,3})", fname)
    if not m:
        return None
    octs = m.groups()
    if all(0 <= int(o) <= 255 for o in octs):
        return ".".join(octs)
    return None

def build_snap_index(ws):
    """Pair every screenshot (from ANY tool) with host/port/scheme/service data so
    the gallery looks the same no matter which tool produced the images."""
    import collections
    snaps_dir = os.path.join(ws, "HTTP_Snaps")
    class_dir = os.path.join(ws, "Classification")

    # authoritative url list (scheme://ip:port) from classification
    urls_by_ip = collections.defaultdict(list)
    http_file = os.path.join(class_dir, "http.txt")
    if os.path.isfile(http_file):
        for line in open(http_file):
            line = line.strip()
            m = re.match(r"(https?)://([\d.]+):(\d+)", line)
            if m:
                urls_by_ip[m.group(2)].append({"scheme": m.group(1), "port": m.group(3), "url": line})

    # products per ip from the component cache
    products_by_ip = collections.defaultdict(set)
    cache = os.path.join(class_dir, ".components_cache.json")
    if os.path.isfile(cache):
        try:
            for c in json.load(open(cache)):
                comp = (c.get("product", "") + " " + c.get("version", "")).strip()
                for ip in c.get("ips", []):
                    if comp:
                        products_by_ip[ip].add(comp)
        except Exception:
            pass

    entries = []
    for root, _, files in os.walk(snaps_dir):
        for fn in sorted(files):
            if not fn.endswith(".png"):
                continue
            rel = os.path.relpath(os.path.join(root, fn), ws)
            tool = rel.split(os.sep)[1] if rel.startswith("HTTP_Snaps" + os.sep) else "unknown"
            ip = _recover_ip(fn)
            low = fn.lower()
            # scheme from filename if present
            scheme = "https" if "https" in low else ("http" if "http" in low else "")
            # port from filename: a 2-5 digit run not part of the IP
            port = ""
            cands = urls_by_ip.get(ip, []) if ip else []
            pm = re.findall(r"(?<!\d)(\d{2,5})(?!\d)", re.sub(r"\d{1,3}[._-]\d{1,3}[._-]\d{1,3}[._-]\d{1,3}", "", fn))
            fileports = set(pm)
            # reconcile with authoritative url list
            url = ""
            if cands:
                pick = None
                for c in cands:
                    if c["port"] in fileports or (scheme and c["scheme"] == scheme and len(cands) == 1):
                        pick = c; break
                pick = pick or cands[0]
                scheme = scheme or pick["scheme"]
                port = pick["port"]; url = pick["url"]
            else:
                port = (sorted(fileports)[0] if fileports else ("443" if scheme == "https" else "80"))
                if ip:
                    url = "%s://%s:%s" % (scheme or "http", ip, port)
            entries.append({"file": rel, "tool": tool, "ip": ip or "?",
                            "port": port, "scheme": scheme or "http", "url": url,
                            "products": sorted(products_by_ip.get(ip, []))})

    # summary + simple distributions for the mini graphs
    by_port = collections.Counter(e["port"] for e in entries)
    by_scheme = collections.Counter(e["scheme"] for e in entries)
    by_host = collections.Counter(e["ip"] for e in entries)
    by_tool = collections.Counter(e["tool"] for e in entries)
    entries.sort(key=lambda e: (e["ip"] == "?", [int(x) for x in e["ip"].split(".")] if e["ip"] != "?" else [999],
                                int(e["port"]) if e["port"].isdigit() else 0))
    return {
        "entries": entries,
        "summary": {
            "total": len(entries),
            "hosts": len([h for h in by_host if h != "?"]),
            "https": by_scheme.get("https", 0),
            "http": by_scheme.get("http", 0),
            "tools": dict(by_tool),
            "by_port": dict(by_port.most_common()),
            "by_host": dict(by_host.most_common(15)),
        },
    }


# ── MODULE scan (reuse nsa_web engine) ───────────────────────────────────────
BUCKET_LABEL = {"overall": "all", "vuln": "vulnerable", "safe": "not_vulnerable"}

def run_module_job(job):
    cfg = job["config"]
    mid = int(cfg["module"])
    targets = nsa_web.parse_targets(cfg.get("targets", ""))
    w = cfg.get("workers", "auto")
    if w in ("auto", "", None, 0, "0"):
        base_w = machine_resources()["recommended_workers"]
        workers = shared(base_w)
        emit(job, "workers: auto → %d (of %d, shared across %d scan[s])"
             % (workers, base_w, active_scan_count()))
    else:
        workers = max(1, int(w))
    m = nsa_web.MODULES[mid]
    total = len(targets)
    emit(job, "=== MODULE %d: %s ===" % (mid, m["name"]))
    emit(job, "command: %s" % nsa_web.cmd_preview(mid))
    emit(job, "%d target(s), %d worker(s)" % (total, workers))
    midx = prog_add(job, m["name"], total)

    # Controllable worker pool: a shared queue + N threads that honor pause/stop.
    import queue as _queue
    q = _queue.Queue()
    for t in targets:
        q.put(t)
    hosts = []; done = [0]
    lock = threading.Lock()

    def worker():
        while True:
            try:
                t = q.get_nowait()
            except _queue.Empty:
                return
            # pause/stop checkpoint before each target
            while job["control"]["pause"] and not job["control"]["stop"]:
                time.sleep(0.3)
            if job["control"]["stop"]:
                q.task_done(); continue
            res = nsa_web.run_target(mid, t[0], t[1])
            with lock:
                done[0] += 1; hosts.append(res); d = done[0]
            prog_step(job, midx)
            tag = "▶ VULNERABLE" if res["status"] == "vuln" else "✓ safe"
            emit(job, "[%d/%d] %s:%s  %s" % (d, total, res["ip"], res["port"], tag))
            for fnd in res["findings"][:6]:
                emit(job, "      → %s" % fnd)
            q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, workers))]
    for th in threads: th.start()
    # pause-aware status while workers run
    while any(th.is_alive() for th in threads):
        if job["control"]["pause"] and job["status"] == "running":
            set_status(job, "paused"); emit(job, "⏸ paused")
        elif not job["control"]["pause"] and job["status"] == "paused":
            set_status(job, "running"); emit(job, "▶ resumed")
        time.sleep(0.4)
    for th in threads: th.join()

    stopped = job["control"]["stop"]
    vuln = [h for h in hosts if h["status"] == "vuln"]
    safe = [h for h in hosts if h["status"] == "safe"]
    job["stats"] = {"overall": len(hosts), "vuln": len(vuln), "safe": len(safe)}
    prog_done(job, midx, "stopped" if stopped else "done")
    # auto-save all buckets: module_results/<bucket>/<module>/<files>
    _save_module_bucket(job, hosts, m, "overall")
    _save_module_bucket(job, hosts, m, "vuln")
    _save_module_bucket(job, hosts, m, "safe")
    emit(job, "%s — %d scanned, %d vulnerable, %d not vulnerable"
         % ("stopped" if stopped else "done", len(hosts), len(vuln), len(safe)))
    emit(job, "saved → module_results/{all,vulnerable,not_vulnerable}/%s/ (shared across all module scans)" % m["slug"])
    if stopped:
        raise StopScan()

def _save_module_bucket(job, hosts, m, bucket):
    if bucket == "vuln":
        sel = [h for h in hosts if h["status"] == "vuln"]
    elif bucket == "safe":
        sel = [h for h in hosts if h["status"] == "safe"]
    else:
        sel = hosts
    # SHARED: module_results/<bucket>/<module-slug>/<ip Port port>.txt
    # (one set of buckets for ALL module scans; each module gets its own subfolder)
    folder = os.path.join(MODRES_DIR, BUCKET_LABEL[bucket], m["slug"])
    os.makedirs(folder, exist_ok=True)
    seen = {}
    for h in sel:
        base = "%s Port %s" % (h["ip"], h["port"])
        n = seen.get(base, 0); seen[base] = n + 1
        fname = base + (".txt" if n == 0 else " (%d).txt" % n)
        status_txt = "VULNERABLE" if h["status"] == "vuln" else "NOT VULNERABLE"
        body = ("%s\nTarget  : %s Port %s\nStatus  : %s\nScanned : %s\nCommand : %s\n%s\n%s\n"
                % (m["name"], h["ip"], h["port"], status_txt, now_iso(),
                   h["command"], "=" * 60, h["output"].rstrip("\n")))
        with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
            f.write(body)
    return len(sel)


# ── RECON job driver ─────────────────────────────────────────────────────────
def run_recon_job(job):
    cfg = job["config"]
    subnets = [s.strip() for s in cfg.get("subnets", []) if s.strip()]
    stages = cfg.get("stages", ["ping", "nmap", "classify", "searchsploit", "snaps"])
    emit(job, "=== RECON on %d subnet(s): %s ===" % (len(subnets), ", ".join(subnets)))
    if "ping" in stages:
        gate(job); stage_ping_sweep(job, subnets)
    if "nmap" in stages:
        gate(job); stage_nmap(job, subnets)
    classified = False
    if "classify" in stages:
        gate(job); classified = stage_classify(job)
    if "searchsploit" in stages and classified:
        gate(job); stage_searchsploit(job)
    if "snaps" in stages and classified:
        gate(job); stage_snaps(job, cfg.get("snap_tool", "auto"))
    job["stats"] = recon_stats(job["workspace"], len(subnets))
    emit(job, "=== RECON COMPLETE ===")

def recon_stats(ws, nsubnets):
    """Precise rollup: hosts up, live hosts with open ports, open ports, services,
    high-risk services, components, exploits, screenshots."""
    comps = exploits = 0
    cache = os.path.join(ws, "Classification", ".components_cache.json")
    try:
        if os.path.isfile(cache):
            data = json.load(open(cache)); comps = len(data)
    except Exception:
        pass
    # open ports / hosts / services from the parsed nmap json
    open_ports = 0; hosts = set(); services = set(); risk = 0
    RISKY = {"microsoft-ds", "netbios-ssn", "ms-wbt-server", "ftp", "telnet",
             "mysql", "ms-sql-s", "redis", "vnc", "rdp", "smb"}
    pj = os.path.join(ws, ".parsed.json")
    try:
        if os.path.isfile(pj):
            for e in json.load(open(pj)):
                open_ports += 1
                ip = e.get("ip") or e.get("address")
                if ip: hosts.add(ip)
                svc = (e.get("service") or e.get("name") or "").lower()
                if svc: services.add(svc)
                if svc in RISKY: risk += 1
    except Exception:
        pass
    # hosts up from ping sweep
    hosts_up = 0
    ps = os.path.join(ws, "ping_sweep.txt")
    try:
        if os.path.isfile(ps):
            for line in open(ps):
                m = re.search(r"(\d+)\s+host", line)
                if m: hosts_up += int(m.group(1))
    except Exception:
        pass
    # exploits from searchsploit output
    ss = os.path.join(ws, "Classification", "searchsploit.txt")
    try:
        if os.path.isfile(ss):
            txt = open(ss, encoding="utf-8", errors="replace").read()
            exploits = txt.count("Exploit Title") - txt.count("No Results Found")
            exploits = max(0, exploits)
    except Exception:
        pass
    return {"subnets": nsubnets, "hosts_up": hosts_up, "live_hosts": len(hosts),
            "open_ports": open_ports, "services": len(services), "risky": risk,
            "components": comps, "exploits": exploits,
            "xmls": _count_files(os.path.join(ws, "nmap_scans"), ".xml"),
            "screenshots": _count_png(os.path.join(ws, "HTTP_Snaps"))}

def svc_counts(ws, top=8):
    """Top open-service counts for the detail-page chart (service -> count)."""
    counts = {}
    pj = os.path.join(ws, ".parsed.json")
    try:
        if os.path.isfile(pj):
            for e in json.load(open(pj)):
                svc = (e.get("service") or e.get("name") or "unknown").lower()
                counts[svc] = counts.get(svc, 0) + 1
    except Exception:
        return {}
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top])

def _count_files(d, ext):
    if not os.path.isdir(d): return 0
    return sum(1 for f in os.listdir(d) if f.endswith(ext))


def run_job_thread(job):
    job["started_at"] = time.time()
    try:
        set_status(job, "running")
        if job["type"] == "module":
            run_module_job(job)
        else:
            run_recon_job(job)
        job["ended_at"] = time.time()
        set_status(job, "done")
        emit(job, "✅ COMPLETED")
    except StopScan:
        job["ended_at"] = time.time()
        kill_job_procs(job)
        # mark any still-running stage as stopped
        for e in job.get("progress", []):
            if e["status"] == "running":
                e["status"] = "stopped"; e["ended"] = time.time()
        set_status(job, "stopped")
        emit(job, "⏹ STOPPED by user")
    except Exception as e:
        job["ended_at"] = time.time()
        emit(job, "[FATAL] %s" % e)
        set_status(job, "error")

def start_job(jtype, name, config, ws_slug=None):
    job = new_job(jtype, name, config, ws_slug=ws_slug)
    threading.Thread(target=run_job_thread, args=(job,), daemon=True).start()
    return job

def start_recon_fanout(name, subnets, stages, snap_tool):
    """Create ONE recon job per subnet, named + foldered by that subnet."""
    jobs = []
    for sn in subnets:
        cfg = {"type": "recon", "subnets": [sn], "stages": stages, "snap_tool": snap_tool}
        # the scan's display name is the subnet itself (optionally prefixed by a user label)
        jname = ("%s — %s" % (name, sn)) if name else sn
        jobs.append(start_job("recon", jname, cfg, ws_slug=sn))
    return jobs


# ── SCHEDULER (in-app) ───────────────────────────────────────────────────────
def load_schedules():
    global SCHEDULES
    if os.path.isfile(SCHED_FILE):
        try:
            with open(SCHED_FILE) as f:
                SCHEDULES = {s["id"]: s for s in json.load(f)}
        except Exception:
            SCHEDULES = {}

def save_schedules():
    with SCHED_LOCK:
        data = list(SCHEDULES.values())
    try:
        with open(SCHED_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def to_utc(date_str, time_str, tz_name):
    """date 'YYYY-MM-DD', time 'HH:MM', tz IANA → aware UTC datetime."""
    naive = datetime.datetime.strptime("%s %s" % (date_str, time_str), "%Y-%m-%d %H:%M")
    if _HAVE_TZ:
        try:
            local = naive.replace(tzinfo=ZoneInfo(tz_name))
            return local.astimezone(datetime.timezone.utc)
        except Exception:
            pass
    return naive.replace(tzinfo=datetime.timezone.utc)

def scheduler_loop():
    while True:
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            due = []
            with SCHED_LOCK:
                for s in SCHEDULES.values():
                    if not s.get("enabled", True):
                        continue
                    try:
                        when = datetime.datetime.fromisoformat(s["next_utc"])
                    except Exception:
                        continue
                    if when <= now:
                        due.append(s)
            for s in due:
                emit_schedule_fire(s)
                advance_schedule(s, now)
            if due:
                save_schedules()
        except Exception:
            pass
        time.sleep(20)

def emit_schedule_fire(s):
    cfg = s["config"]
    label = s.get("name", cfg.get("type", "scan"))
    if cfg.get("type") == "recon":
        subnets = [x for x in cfg.get("subnets", []) if x]
        # fan out into one scheduled instance per subnet
        start_recon_fanout("%s (scheduled)" % label, subnets,
                           cfg.get("stages", ["ping", "nmap", "classify", "searchsploit", "snaps"]),
                           cfg.get("snap_tool", "auto"))
    else:
        start_job(cfg["type"], "%s (scheduled)" % label, cfg)
    s["last_run"] = now_iso()

def advance_schedule(s, now):
    rec = s.get("recurrence", "once")
    if rec == "once":
        s["enabled"] = False
        return
    try:
        when = datetime.datetime.fromisoformat(s["next_utc"])
    except Exception:
        when = now
    step = {"daily": 1, "weekly": 7}.get(rec, 0)
    while when <= now:
        when = when + datetime.timedelta(days=step)
    s["next_utc"] = when.isoformat()


# ── HTTP handler ─────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    def log_message(self, *a): pass

    def _send(self, code, ctype, body):
        if isinstance(body, str): body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try: self.wfile.write(body)
        except Exception: pass

    def _json(self, obj, code=200):
        self._send(code, "application/json", json.dumps(obj))

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        if not n: return {}
        try: return json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except Exception: return {}

    # ---- GET ----
    def do_GET(self):
        u = urlparse(self.path); path = u.path; q = parse_qs(u.query)
        if path == "/" or path.startswith("/?"):
            try:
                with open(UI_FILE, encoding="utf-8") as f: ui = f.read()
            except Exception as e:
                ui = "<h1>ui.html missing</h1><pre>%s</pre>" % html.escape(str(e))
            return self._send(200, "text/html; charset=utf-8", ui)
        if path == "/api/modules":
            data = [dict(id=i, name=m["name"], cat=m["cat"], port=m["port"],
                         slug=m["slug"], cmd=nsa_web.cmd_preview(i))
                    for i, m in sorted(nsa_web.MODULES.items())]
            return self._json(data)
        if path == "/api/ping":
            return self._json({"ok": True, "t": time.time()})
        if path == "/api/timezones":
            return self._json(self._timezones())
        if path == "/api/resources":
            return self._json(machine_resources())
        if path == "/api/sysstats":
            return self._json(system_stats())
        if path == "/api/preflight":
            return self._json(self._preflight())
        if path == "/api/tools":
            return self._json({"snap_tools": available_snap_tools(),
                               "searchsploit": have("searchsploit"),
                               "nmap": have("nmap")})
        if path == "/api/jobs":
            return self._json(self._jobs_list())
        if path == "/api/trash":
            return self._json(self._jobs_list(trashed=True))
        if path == "/api/job":
            jid = (q.get("id") or [""])[0]
            job = JOBS.get(jid)
            if not job: return self._json({"error": "unknown job"}, 404)
            return self._json(self._job_public(job))
        if path == "/api/job/log":
            return self._job_log(q)
        if path == "/api/schedules":
            with SCHED_LOCK:
                return self._json(list(SCHEDULES.values()))
        if path == "/api/results":
            return self._results(q)
        if path == "/api/module_results":
            return self._json(self._module_results())
        if path.startswith("/mr/"):
            return self._serve_modres(path)
        if path == "/api/shots":
            jid = (q.get("id") or [""])[0]
            job = JOBS.get(jid)
            if not job: return self._json({"error": "unknown job"}, 404)
            try:
                return self._json(build_snap_index(job["workspace"]))
            except Exception as e:
                return self._json({"error": str(e), "entries": [], "summary": {}}, 200)
        if path.startswith("/ws/"):
            return self._serve_ws(path)
        return self._send(404, "text/plain", "not found")

    # ---- POST ----
    def do_POST(self):
        path = urlparse(self.path).path
        b = self._body()
        if path == "/api/scan/module":
            if int(b.get("module", 0)) not in nsa_web.MODULES:
                return self._json({"error": "bad module"}, 400)
            job = start_job("module", b.get("name", ""), {
                "type": "module", "module": int(b["module"]),
                "targets": b.get("targets", ""), "workers": b.get("workers", 10)})
            return self._json({"id": job["id"]})
        if path == "/api/scan/recon":
            subnets = [s for s in re.split(r"[,\s]+", b.get("subnets", "")) if s]
            if not subnets:
                return self._json({"error": "no subnets"}, 400)
            jobs = start_recon_fanout(
                b.get("name", ""), subnets,
                b.get("stages", ["ping", "nmap", "classify", "searchsploit", "snaps"]),
                b.get("snap_tool", "auto"))
            ids = [j["id"] for j in jobs]
            return self._json({"ids": ids, "id": ids[0] if ids else None})
        if path == "/api/job/control":
            jid = b.get("id"); action = b.get("action")
            job = JOBS.get(jid)
            if not job: return self._json({"error": "unknown job"}, 404)
            ctl = job.get("control")
            if ctl is None:
                return self._json({"error": "job not controllable"}, 400)
            if action == "pause":
                ctl["pause"] = True
            elif action == "resume":
                ctl["pause"] = False
            elif action == "stop":
                ctl["stop"] = True; ctl["pause"] = False
                kill_job_procs(job)
            else:
                return self._json({"error": "bad action"}, 400)
            return self._json({"ok": True, "status": job.get("status")})
        if path in ("/api/job/trash", "/api/job/restore", "/api/job/delete"):
            jid = b.get("id"); job = JOBS.get(jid)
            if not job: return self._json({"error": "unknown job"}, 404)
            if path == "/api/job/trash":
                ctl = job.get("control")
                if ctl and job.get("status") in ("running", "paused", "queued"):
                    ctl["stop"] = True; kill_job_procs(job)
                job["trashed"] = True; write_meta(job)
                return self._json({"ok": True})
            if path == "/api/job/restore":
                job["trashed"] = False; write_meta(job)
                return self._json({"ok": True})
            if path == "/api/job/delete":            # permanent
                ws = job.get("workspace")
                with JOBS_LOCK:
                    JOBS.pop(jid, None)
                try:
                    if ws and os.path.isdir(ws) and os.path.abspath(ws).startswith(os.path.abspath(WS_ROOT) + os.sep):
                        shutil.rmtree(ws, ignore_errors=True)
                except Exception:
                    pass
                return self._json({"ok": True})
        if path == "/api/schedule":
            return self._add_schedule(b)
        if path == "/api/schedule/delete":
            sid = b.get("id")
            with SCHED_LOCK:
                SCHEDULES.pop(sid, None)
            save_schedules()
            return self._json({"ok": True})
        if path == "/api/schedule/toggle":
            sid = b.get("id")
            with SCHED_LOCK:
                if sid in SCHEDULES:
                    SCHEDULES[sid]["enabled"] = not SCHEDULES[sid].get("enabled", True)
            save_schedules()
            return self._json({"ok": True})
        return self._send(404, "text/plain", "not found")

    # ---- helpers ----
    def _preflight(self):
        # modules: cmd modules are inline (always present); probe/ipmi/smtp need their file
        modules = []
        for mid, m in sorted(nsa_web.MODULES.items()):
            runner = m["runner"]
            if runner == "cmd":
                present, detail = True, "inline (nmap/redis/snmp)"
            else:
                probe = m.get("probe") or ("_nsa_%s.py" % ("ipmi" if runner == "ipmi" else "smtp"))
                path = os.path.join(BASE_DIR, "NSA", probe)
                present, detail = os.path.isfile(path), probe
            modules.append({"id": mid, "name": m["name"], "present": present, "detail": detail})
        # project files
        files = []
        for rel in ("ui.html", "nsa_web.py", "engine/sn_parse_xmls.py",
                    "engine/sn_classify.py", "engine/sn_comp_tsv.py"):
            files.append({"name": rel, "present": os.path.isfile(os.path.join(BASE_DIR, rel))})
        # cli tools
        tools = []
        for name, purpose, level in TOOLS_USED:
            path = shutil.which(name)
            tools.append({"name": name, "purpose": purpose, "level": level,
                          "present": bool(path), "path": path or ""})
        # special-cased binaries
        chrome = find_chrome(); aq = find_aquatone()
        tools.append({"name": "chromium/chrome", "purpose": "headless browser for aquatone screenshots",
                      "level": "recon", "present": bool(chrome), "path": chrome or ""})
        tools.append({"name": "aquatone", "purpose": "HTTP screenshots (needs chromium)",
                      "level": "recon", "present": bool(aq), "path": aq or ""})
        missing_required = [t["name"] for t in tools if t["level"] == "required" and not t["present"]]
        return {
            "resources": machine_resources(),
            "modules": modules,
            "files": files,
            "tools": tools,
            "summary": {
                "modules_total": len(modules),
                "modules_present": sum(1 for x in modules if x["present"]),
                "files_present": sum(1 for x in files if x["present"]),
                "files_total": len(files),
                "tools_present": sum(1 for x in tools if x["present"]),
                "tools_total": len(tools),
                "required_ok": not missing_required,
                "missing_required": missing_required,
            },
        }

    def _timezones(self):
        if _HAVE_TZ:
            try:
                return sorted(available_timezones())
            except Exception:
                pass
        return ["UTC", "Asia/Kolkata", "America/New_York", "Europe/London",
                "America/Los_Angeles", "Asia/Dubai", "Asia/Singapore", "Australia/Sydney"]

    def _jobs_list(self, trashed=False):
        with JOBS_LOCK:
            jobs = [j for j in JOBS.values() if bool(j.get("trashed")) == trashed]
        out = []
        for j in sorted(jobs, key=lambda x: x["id"], reverse=True):
            started = j.get("started_at"); ended = j.get("ended_at")
            runtime = round((ended or time.time()) - started, 1) if started else None
            entry = {"id": j["id"], "type": j["type"], "name": j.get("name"),
                     "status": j.get("status"), "created": j.get("created"),
                     "started_at": started, "runtime": runtime,
                     "config": j.get("config", {}), "stats": j.get("stats", {})}
            # compact live progress for running/paused jobs
            if j.get("status") in ("running", "paused"):
                prog = j.get("progress", [])
                cfg = j.get("config", {})
                planned = (len([x for x in cfg.get("stages", []) ]) if j["type"] == "recon"
                           else 1) or len(prog) or 1
                cur = next((e["name"] for e in prog if e["status"] == "running"), None)
                started = sum(1 for e in prog if e["status"] != "pending")
                d = sum(e["done"] for e in prog); tot = sum(e["total"] for e in prog)
                entry["prog"] = {"stage": min(started, planned), "planned": planned,
                                 "cur": cur or "…", "pct": round(100 * d / tot) if tot else 0}
            out.append(entry)
        return out

    def _job_public(self, job):
        started = job.get("started_at"); ended = job.get("ended_at")
        runtime = None
        if started:
            runtime = (ended or time.time()) - started
        # expose progress stages without internal timestamps the UI doesn't need raw
        prog = []
        for e in job.get("progress", []):
            el = (e.get("ended") or time.time()) - e["started"] if e.get("started") else 0
            prog.append({"name": e["name"], "status": e["status"],
                         "done": e["done"], "total": e["total"], "elapsed": round(el, 1)})
        return {"id": job["id"], "type": job["type"], "name": job.get("name"),
                "status": job.get("status"), "created": job.get("created"),
                "stats": job.get("stats", {}), "config": job.get("config", {}),
                "progress": prog, "runtime": round(runtime, 1) if runtime is not None else None,
                "paused": job.get("control", {}).get("pause", False),
                "log_len": len(job.get("log", []))}

    def _job_log(self, q):
        jid = (q.get("id") or [""])[0]
        start = int((q.get("from") or ["0"])[0])
        job = JOBS.get(jid)
        if not job: return self._json({"error": "unknown job"}, 404)
        # short long-poll: wait up to ~8s for new lines
        for _ in range(16):
            with JOBS_LOCK:
                log = job["log"]; n = len(log)
                if n > start or job["status"] in ("done", "error"):
                    lines = log[start:n]
                    return self._json({"lines": lines, "next": n,
                                       "status": job["status"], "stats": job.get("stats", {})})
            time.sleep(0.5)
        with JOBS_LOCK:
            n = len(job["log"])
            return self._json({"lines": job["log"][start:n], "next": n,
                               "status": job["status"], "stats": job.get("stats", {})})

    def _add_schedule(self, b):
        try:
            when = to_utc(b["date"], b["time"], b.get("tz", "UTC"))
        except Exception as e:
            return self._json({"error": "bad date/time: %s" % e}, 400)
        sid = uuid.uuid4().hex[:10]
        cfg = b.get("config", {})
        s = {"id": sid, "name": b.get("name", cfg.get("type", "scan")),
             "config": cfg, "tz": b.get("tz", "UTC"),
             "local": "%s %s" % (b.get("date"), b.get("time")),
             "recurrence": b.get("recurrence", "once"),
             "next_utc": when.isoformat(), "enabled": True, "last_run": None}
        with SCHED_LOCK:
            SCHEDULES[sid] = s
        save_schedules()
        return self._json({"ok": True, "id": sid, "next_utc": when.isoformat()})

    def _results(self, q):
        jid = (q.get("id") or [""])[0]
        job = JOBS.get(jid)
        if not job: return self._json({"error": "unknown job"}, 404)
        ws = job["workspace"]; rel = lambda p: os.path.relpath(p, ws)
        # live stats (recon): recompute from artifacts so the detail page is
        # accurate during the scan, not only after it finishes
        stats = job.get("stats", {})
        if job["type"] == "recon":
            try:
                nsub = len((job.get("config") or {}).get("subnets", [])) or 1
                live = recon_stats(ws, nsub)
                if any(live.values()):
                    stats = live
            except Exception:
                pass
        res = {"id": jid, "type": job["type"], "status": job.get("status"),
               "stats": stats, "svc_breakdown": svc_counts(ws), "files": {}}
        # recon artifacts
        cdir = os.path.join(ws, "Classification")
        if os.path.isdir(cdir):
            res["dashboard"] = "Classification/dashboard.html" if os.path.isfile(os.path.join(cdir, "dashboard.html")) else None
            res["class_files"] = sorted(f for f in os.listdir(cdir) if not f.startswith("."))
        xdir = os.path.join(ws, "nmap_scans")
        if os.path.isdir(xdir):
            res["xmls"] = sorted(f for f in os.listdir(xdir) if f.endswith(".xml"))
        if os.path.isfile(os.path.join(ws, "ping_sweep.txt")):
            res["ping_sweep"] = "ping_sweep.txt"
        # screenshots
        shots = []
        sdir = os.path.join(ws, "HTTP_Snaps")
        if os.path.isdir(sdir):
            for root, _, files in os.walk(sdir):
                for fn in files:
                    if fn.endswith(".png"):
                        shots.append(rel(os.path.join(root, fn)))
        res["screenshots"] = sorted(shots)
        # module results — module_results/<bucket>/<module>/<files>
        mdir = os.path.join(ws, "module_results")
        if os.path.isdir(mdir):
            res["module_folders"] = {}
            for bucket in sorted(os.listdir(mdir)):
                bpath = os.path.join(mdir, bucket)
                if not os.path.isdir(bpath):
                    continue
                for mod in sorted(os.listdir(bpath)):
                    mpath = os.path.join(bpath, mod)
                    if os.path.isdir(mpath):
                        res["module_folders"]["%s/%s" % (bucket, mod)] = \
                            len([f for f in os.listdir(mpath) if f.endswith(".txt")])
        return self._json(res)

    def _module_results(self):
        """Shared module_results tree: {bucket: {module: {count, files:[...]}}}."""
        tree = {}
        for bucket in ("all", "vulnerable", "not_vulnerable"):
            bpath = os.path.join(MODRES_DIR, bucket)
            if not os.path.isdir(bpath):
                continue
            tree[bucket] = {}
            for mod in sorted(os.listdir(bpath)):
                mpath = os.path.join(bpath, mod)
                if os.path.isdir(mpath):
                    files = sorted(f for f in os.listdir(mpath) if f.endswith(".txt"))
                    tree[bucket][mod] = {"count": len(files), "files": files}
        return {"tree": tree, "root": os.path.relpath(MODRES_DIR, BASE_DIR)}

    def _serve_modres(self, path):
        # /mr/<bucket>/<module>/<file>
        rel = path[len("/mr/"):]
        full = safe_join(MODRES_DIR, rel)
        if not full or not os.path.isfile(full):
            return self._send(404, "text/plain", "no file")
        try:
            with open(full, "rb") as f: data = f.read()
        except Exception:
            return self._send(500, "text/plain", "read error")
        self.send_response(200)
        self.send_header("Content-Type", self._ctype(full))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try: self.wfile.write(data)
        except Exception: pass

    def _serve_ws(self, path):
        # /ws/<jid>/<relpath>
        rest = path[len("/ws/"):]
        if "/" not in rest:
            return self._send(404, "text/plain", "not found")
        jid, rel = rest.split("/", 1)
        job = JOBS.get(jid)
        if not job:
            return self._send(404, "text/plain", "unknown job")
        full = safe_join(job["workspace"], rel)
        if not full or not os.path.isfile(full):
            return self._send(404, "text/plain", "no file")
        ctype = self._ctype(full)
        try:
            with open(full, "rb") as f: data = f.read()
        except Exception:
            return self._send(500, "text/plain", "read error")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try: self.wfile.write(data)
        except Exception: pass

    def _ctype(self, p):
        p = p.lower()
        if p.endswith(".html"): return "text/html; charset=utf-8"
        if p.endswith(".png"):  return "image/png"
        if p.endswith(".json"): return "application/json"
        if p.endswith(".xml"):  return "application/xml"
        return "text/plain; charset=utf-8"


# ── startup ──────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Recon Console — unified local scanner UI")
    ap.add_argument("--port", type=int, default=8800)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("[!] localhost only — this console runs scan commands on the host."); sys.exit(1)

    load_existing_workspaces()
    load_schedules()
    threading.Thread(target=scheduler_loop, daemon=True).start()

    url = "http://%s:%d/" % (args.host, args.port)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("  Argus — Network Recon & Scan Console  →  %s" % url)
    print("  Workspaces: %s" % WS_ROOT)
    if not _HAVE_TZ:
        print("  [note] zoneinfo unavailable — timezone list limited")
    print("  (Ctrl-C to stop)")
    if not args.no_browser:
        threading.Thread(target=lambda: (time.sleep(0.7), webbrowser.open(url)), daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped.")


if __name__ == "__main__":
    main()
