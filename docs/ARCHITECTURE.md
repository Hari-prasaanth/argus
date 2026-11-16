# Argus — Architecture

Argus is a single-process, dependency-free Python app. It replaces the interactive
bash menus of two existing tools with a web UI + a job runner, **without changing
their scan logic**.

```
 Browser (ui.html, vanilla JS)
        │  fetch / NDJSON log polling
        ▼
 console.py  ── ThreadingHTTPServer (HTTP/1.0, localhost only)
   ├── job runner (threads)
   │     ├── recon stages ── nmap / searchsploit / eyewitness·aquatone·gowitness
   │     │                   + engine/sn_*.py  (SweepNinja, verbatim)
   │     └── module scan  ── nsa_web.run_target → NSA/_nsa_*.py probes
   ├── in-app scheduler (thread, zoneinfo) — recon only
   ├── live system monitor (/api/sysstats — CPU/RAM/load from /proc)
   ├── workspaces/<id>/  (per-scan artifacts, meta.json, scan.log; soft-delete via trashed flag)
   └── static file serving for dashboard.html / screenshots (path-traversal guarded)
```

## Components

| File / dir | Role |
|------------|------|
| `console.py` | HTTP server, job runner, scheduler, resource detection, results/file serving. |
| `ui.html` | The entire single-page UI (served as-is). |
| `nsa_web.py` | NSA module registry + per-target runner, imported as a library. |
| `NSA/_nsa_*.py` | The NSA probe scripts — **unchanged**. New modules plug in here (see below). |
| `engine/sn_parse_xmls.py` | Nmap-XML → JSON parser, extracted verbatim from SweepNinja. |
| `engine/sn_classify.py` | Classifier + `dashboard.html` generator, verbatim from SweepNinja. |
| `engine/sn_comp_tsv.py` | Component TSV builder for searchsploit, verbatim. |

## Jobs

A scan is a job with its own `workspaces/<id>/` directory and an in-memory log.
The runner streams log lines; the browser polls `/api/job/log?id=&from=` (a short
long-poll) and renders them in the terminal pane. On completion the job writes
`meta.json`, so history survives a restart (`load_existing_workspaces()` repopulates
the registry on boot).

## Fidelity to the original tools

- SweepNinja's Python (XML parse, classify/dashboard, component TSV) is extracted
  **byte-for-byte** into `engine/`.
- NSA probes are copied unchanged; `nsa_web.run_target` replicates the original
  module dispatch and vuln/safe classification.
- External commands (nmap, searchsploit, screenshot tools) use the **same flags**.
- The only intentional enhancement: after searchsploit runs, classification is
  re-run so exploit results are embedded in the dashboard.

## Extensibility (modules)

Modules are declarative entries in `nsa_web.py → MODULES`. A `runner="probe"` module is a
standalone `NSA/_nsa_<slug>.py` taking `ip port`; any non-empty stdout line is a finding
(→ VULNERABLE), info-key lines are detail, empty output = clean. Adding a module is one file
+ one dict entry — no changes to `console.py` or the UI, and the new module auto-appears on
Preflight and in the Module Scan dropdown. `runner="cmd"` modules (1–6) instead add a branch
to `build_cmd()` + `classify_cmd()`. See the README's *Extending Argus* section for the full
contract and an AI prompt template.

## Soft-delete & trash

Each job carries a `trashed` flag (persisted in `meta.json`). `/api/jobs` returns live jobs,
`/api/trash` returns trashed ones. `/api/job/trash` stops a running job and flags it;
`/api/job/restore` clears the flag; `/api/job/delete` removes the job and `rmtree`s its
workspace (guarded to stay inside `workspaces/`).

## Concurrency model

`machine_resources()` reads `os.cpu_count()` and `/proc/meminfo` and derives:

- `recommended_slots` — nmap subnet parallelism (`cores×ram/4`, 1–16).
- `recommended_workers` — module-scan parallel targets (`~2×cores`, RAM-bounded, ≤32).
- `screenshot_threads` — headless-browser threads (`~1/GB`, ≤ cores, ≤8).

The nmap pool is CIDR-weighted via `cidr_slot_cost()` (a /8 = 8 slots, /24 = 1), so a
single large network can't starve the box while small ones finish fast.

## Security model

- Binds to `127.0.0.1` only; refuses any other host.
- Workspace file serving normalizes paths and rejects traversal outside the scan's
  own directory.
- No authentication is implemented — it is a localhost tool. Expose it only via an
  SSH tunnel.
