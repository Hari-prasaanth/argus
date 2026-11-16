# Argus — Usage Guide

## Running

```bash
sudo ./console.sh                       # localhost:8800, opens browser
sudo ./console.sh --no-browser --port 9000
```

`sudo` is needed because several scan stages require root (raw/UDP nmap, `nmap -A -p-`, NFS mount). The UI itself renders fine without root if you only want to look around.

Deep-link to any page with a hash: `http://127.0.0.1:8800/#preflight`, `#newscan`, `#trash`, etc. The sidebar collapses to an icon rail (hamburger ☰); its footer shows a live CPU / RAM / load monitor.

---

## 1. Preflight

Open this first. It shows:

- A green banner if all **required** tools are present (red, listing what's missing, otherwise).
- **Resource tiles** — CPU cores, total/free RAM, and the auto-computed *workers / nmap slots / screenshot threads* for this machine.
- **CLI tools** — every tool Argus can call, with a green/red dot, its purpose, criticality (`required` / `recon` / `module` / `optional`), and resolved path.
- **Modules (25)** — a dot per module (green = its probe file is present).
- **Project files** — the engine/UI files Argus needs.

The blinking green dot in the top bar polls the server every few seconds; it turns solid red if the console stops.

---

## 2. New Scan

### Subnet Recon
1. Enter one or more subnets (comma or newline separated): `192.168.1.0/24, 10.0.0.0/16`.
2. Tick the stages you want:
   - **Ping sweep** — `nmap -sn` per subnet.
   - **Nmap** — `nmap -T4 -A -p- --min-rate 1000 --max-retries 2 -oX …`, run in a CIDR-weighted parallel pool.
   - **Classify** — parse the XML into `http.txt`, per-service files, a vuln checklist, `components.txt`, and `dashboard.html`.
   - **Searchsploit** — match discovered components to Exploit-DB (the dashboard is rebuilt afterwards so exploits appear in it).
   - **HTTP screenshots** — eyewitness / aquatone / gowitness.
3. Pick a screenshot tool (or `auto`).
4. **▶ Run recon** → the scan starts in the background and you're taken to the
   **Dashboard**, where its live terminal, progress, and results appear. (Recon output
   is **not** shown on the New Scan page.)

Recon and Module scans run independently — each tab has its own Run button, and
starting a module scan never blocks a running recon (and vice-versa). When both run at
once, workers / nmap-slots / screenshot-threads are divided between them automatically.

### Module Scan
1. Pick one of the 25 modules — the exact command it will run is shown.
2. Paste targets (`x.x.x.x Port xx`, one per line) or upload a file.
3. **Workers** defaults to `auto` (sized to the machine). Type a number to override.
4. **Run now.** Per-host output is saved automatically under
   `module_results/<bucket>/<module>/`, where `<bucket>` is `all`, `vulnerable`, or
   `not_vulnerable`, e.g. `module_results/vulnerable/smb_signing/10.0.0.5 Port 445.txt`.

### Live control (both scan types)
Once a scan starts the Run button locks (so you can't double-start it) and a control
panel appears with:

- a big **RUNNING / PAUSED / COMPLETED / STOPPED** status and a running clock;
- **Pause / Resume** — stops dispatching new work; in-flight probes finish, then it holds;
- **Stop** — cancels the scan and terminates running `nmap`/screenshot processes;
- a **per-stage progress bar** (ping / nmap / classify / searchsploit / screenshots, or
  the module across its targets) with each stage's done/total, elapsed time, and ETA.

---

## 3. Scheduling (recon only)

Scheduling is built into the **Subnet Recon** form — there is no separate Schedule page, and
module scans are run on demand only. Fill the recon form (subnets + stages), then click
**◷ Schedule instead** to reveal:

- **Date** — calendar picker.
- **Time** — local time.
- **Timezone** — start typing a city; `chennai`, `salem`, `mumbai`, `dubai`, `london`, `nyc`, etc. resolve to the correct IANA zone, or type the zone directly.
- **Recurrence** — once / daily / weekly.

Click **◷ Schedule recon**. Scheduled scans appear in the **Scheduled recon** panel on the
Dashboard with their next run (in UTC), and can be enabled/disabled or deleted. A schedule with
N subnets fans out into N independent instances when it fires. The scheduler runs **inside the
console process** — keep `console.py` running (e.g. in `tmux`/`screen`) for schedules to fire.

---

## 4. Dashboard (recon hub)

The Dashboard is where all recon output lives. It shows headline metrics (recon scans,
running, hosts up, open ports, exploits), a **live board** (one row per subnet with a
spinner, status, `step X/Y · stage · pct%` while running, the host count after each subnet
once the ping sweep returns, a ticking clock, and a hover **🗑 delete**), the **Scheduled
recon** panel, and **⊕ All subnets**. Click a row to open its **full detail page**:

- If the scan is still running: the live terminal, big status, Pause/Stop, and per-stage
  progress appear here.
- **Precise stat tiles** — hosts up, live hosts (with open ports), open ports, services,
  **high-risk services**, exploits, components, screenshots, nmap XML. Risk and exploit
  tiles turn red when non-zero.
- An **open-services bar chart**.
- The **recon dashboard** (`dashboard.html`) rendered inline, plus an "open in new tab" link.
- **Classification files**, **ping sweep**, and **nmap XML** as direct links.
- The **screenshot report** (see below).

**⊕ All subnets** gives a combined view: aggregate tiles + a merged open-services chart
across every recon scan, a table of all scans, and one merged screenshot gallery.

Deleting a scan (🗑 on its row) moves it to the **Trash** page, where it can be restored or
deleted permanently (which also removes its workspace).

Module scans do **not** appear on the Dashboard — their output stays on the New Scan ›
Module page, and their files accumulate under the shared `module_results/` tree.

### Screenshot report (under a recon scan's detail)

Tool-agnostic — whether the shots came from aquatone, eyewitness, or gowitness, you get
the same view:

- Summary tiles (total / hosts / HTTPS / HTTP / distinct ports).
- **By-port** and **by-host** bar graphs.
- **Group by** host, port, or service, plus a filter box (IP, URL, port, product).
- Each card shows the scheme badge, `IP:port`, detected product/version (matched from
  classification), the capturing tool, and an "open" link. High-risk service ports get
  a red border.

Click any thumbnail to enlarge.

### Automatic fallback
The HTTP-snaps stage tries your chosen tool first; if it produces **zero** screenshots
(tool crash, missing chromium, etc.) Argus automatically falls back to the next
available tool — aquatone ⇄ eyewitness ⇄ gowitness — until one succeeds, and logs each
attempt in the live terminal.

---

## Tips

- **Workers vs nmap slots:** *workers* = parallel targets in a module scan; *nmap slots* = parallel subnets in recon (a /8 consumes more slots than a /24, so big networks don't all run at once).
- **Stuck scheduler?** It only fires while the console is running. For always-on scheduling, run Argus under `tmux` or as a service.
- **Nothing happens on a stage?** Check Preflight — the required tool is probably missing; install it and re-check.
