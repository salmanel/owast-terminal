#!/usr/bin/env python3
"""
TSA Web Tester — Terminal UI (v1.0.1 + Export submenu)

Baseline:
  1) Quick scan
  2) Advanced scan
  3) List latest reports
  4) View a report in terminal (JSON)
  5) Open HTML / Export (MD, CSV, PDF, Bundle)
  6) Show raw JSON of a report
  7) Delete a report
  8) Open latest HTML report

Notes
- CSV writer uses commas + proper quoting (no “all in column A” issue).
- Markdown matches your earlier preferred layout.
- PDF uses WeasyPrint if installed; else falls back to an HTML you can print to PDF.
"""

from __future__ import annotations

import sys, os, json, time, subprocess, webbrowser, re, tempfile, csv, datetime
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any
from colorama import init as colorama_init, Fore, Style
from tabulate import tabulate

try:
    import yaml  # PyYAML for advanced config
except Exception:
    yaml = None

# Optional PDF support
try:
    from weasyprint import HTML as _WHTML  # type: ignore
except Exception:  # nosec - optional dep
    _WHTML = None

colorama_init(autoreset=True)

# ---------- Paths ----------
REPO_ROOT   = Path(__file__).resolve().parent.parent
CLI_PATH    = REPO_ROOT / "cli.py"
DEFAULT_CFG = REPO_ROOT / "config.yaml"
REPORTS_DIR = REPO_ROOT / "reports"
PYTHON      = sys.executable

def info(msg: str): print(Fore.CYAN + msg + Style.RESET_ALL)
def ok(msg: str):   print(Fore.GREEN + msg + Style.RESET_ALL)
def warn(msg: str): print(Fore.YELLOW + msg + Style.RESET_ALL)
def err(msg: str):  print(Fore.RED + msg + Style.RESET_ALL)

# ---------- Banner ----------
BANNER_LINES = [
  r" .___________.   _______.    ___      ____    __    ____  _______ .______   .___________. _______      _______..___________. _______ .______         ",
  r" |           |  /       |   /   \     \   \  /  \  /   / |   ____||   _  \  |           ||   ____|    /       ||           ||   ____||   _  \        ",
  r" `---|  |----` |   (----`  /  ^  \     \   \/    \/   /  |  |__   |  |_)  | `---|  |----`|  |__      |   (----``---|  |----`|  |__   |  |_)  |       ",
  r"     |  |       \   \     /  /_\  \     \            /   |   __|  |   _  <      |  |     |   __|      \   \        |  |     |   __|  |      /        ",
  r"     |  |   .----)   |   /  _____  \     \    /\    /    |  |____ |  |_)  |     |  |     |  |____ .----)   |       |  |     |  |____ |  |\  \---.    ",
  r"     |  |   |_______/   /__/     \__\     \__/  \__/     |_______||______/      |__|     |_______||_______/        |__|     |_______|| _| `.____|    ",
  r"=====|__|=== TSA WEB TESTER — terminal interface =================================================================================================   ",
]

def print_banner():
    shades = [Style.DIM, Style.DIM, "", "", Style.BRIGHT, Style.BRIGHT, Style.BRIGHT]
    print()
    for line, shade in zip(BANNER_LINES, shades):
        print(shade + Fore.CYAN + line + Style.RESET_ALL)

def ensure_paths() -> bool:
    print_banner()
    ok("Terminal Interface ready")
    if not CLI_PATH.exists():
        err(f"cli.py not found at: {CLI_PATH}")
        print("Expected at project root alongside: config.yaml, core/, reports/")
        return False
    if yaml is None:
        warn("PyYAML not installed. Advanced Scan will be limited. (pip install pyyaml)")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return True

REPORTS_LINE = re.compile(r"Reports saved:\s*(?P<json>[^|]+\.json)\s*\|\s*(?P<html>.+\.html)", re.I)

# ---------- Core helpers ----------

def run_cli_scan(url: str, *, config: Optional[Path]=None, out_dir: Optional[Path]=None,
                 debug=False, details=False) -> Tuple[Optional[Path], Optional[Path], int]:
    args = [PYTHON, str(CLI_PATH), "--url", url]
    if config:   args += ["--config", str(config)]
    if out_dir:  args += ["--out", str(out_dir)]
    if debug:    args += ["--debug"]
    if details:  args += ["--details"]

    print(Fore.MAGENTA + "\n> " + " ".join(map(str, args)) + Style.RESET_ALL)
    json_path = html_path = None

    proc = subprocess.Popen(args, cwd=str(REPO_ROOT), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            line_strip = line.rstrip("\n")
            print(line_strip)
            m = REPORTS_LINE.search(line_strip)
            if m:
                try:
                    jp = Path(m.group("json"))
                    hp = Path(m.group("html"))
                    json_path = (REPO_ROOT / jp).resolve() if not jp.is_absolute() else jp.resolve()
                    html_path = (REPO_ROOT / hp).resolve() if not hp.is_absolute() else hp.resolve()
                except Exception:
                    pass
        proc.wait()
    except KeyboardInterrupt:
        warn("\nInterrupted. Sending SIGINT to cli.py…")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    return json_path, html_path, proc.returncode if proc and proc.returncode is not None else 1

def list_report_files(limit: int = 25) -> List[Path]:
    return sorted(REPORTS_DIR.glob("report_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]

def latest_report_json() -> Optional[Path]:
    files = list_report_files(1)
    return files[0] if files else None

def load_report(json_path: Path) -> Optional[dict]:
    try:
        return json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as e:
        err(f"Failed to read {json_path}: {e}")
        return None

def summarize_report(r: dict) -> str:
    findings = r.get("findings", [])
    high = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")
    med  = sum(1 for f in findings if (f.get("severity") or "").upper() == "MEDIUM")
    info_n = sum(1 for f in findings if (f.get("severity") or "").upper() in ("LOW","INFO"))
    return f"Pages: {r.get('crawled_pages', 0)} | Forms: {r.get('discovered_forms', 0)} | HIGH: {high} | MEDIUM: {med} | INFO: {info_n}"

def _bucketize(findings: List[dict]) -> Dict[str, List[dict]]:
    buckets = {"HIGH": [], "MEDIUM": [], "INFO": []}
    for f in findings:
        sev = (f.get("severity") or "").upper()
        if sev == "HIGH":
            buckets["HIGH"].append(f)
        elif sev == "MEDIUM":
            buckets["MEDIUM"].append(f)
        else:
            buckets["INFO"].append(f)
    return buckets

def pretty_print_findings_by_severity(r: dict, limit_per_bucket: int = 100):
    findings = r.get("findings", [])
    if not findings:
        ok("No findings 🎉")
        return
    buckets = _bucketize(findings)

    def emit(name: str, color, items: List[dict]):
        if not items:
            return
        print(color + f"\n=== {name} ({len(items)}) ===" + Style.RESET_ALL)
        rows = [[it.get("severity",""), it.get("category",""), it.get("url",""),
                 it.get("param",""), it.get("evidence","")] for it in items[:limit_per_bucket]]
        print(tabulate(rows, headers=["Severity","Category","URL","Param","Evidence"], tablefmt="fancy_grid"))
        if len(items) > limit_per_bucket:
            print(f"... and {len(items) - limit_per_bucket} more")

    emit("HIGH",   Fore.RED,    buckets["HIGH"])
    emit("MEDIUM", Fore.YELLOW, buckets["MEDIUM"])
    emit("INFO",   Fore.CYAN,   buckets["INFO"])

def open_html_for_json(json_path: Path):
    html_candidate = json_path.with_suffix(".html")
    if html_candidate.exists():
        webbrowser.open(html_candidate.as_uri())
        ok(f"Opened {html_candidate}")
    else:
        warn(f"No matching HTML report at {html_candidate}")

def choose_report_path(prompt: str) -> Optional[Path]:
    files = list_report_files(50)
    if not files:
        warn("No reports found.")
        return None
    print("\nAvailable reports (latest first):")
    for i, p in enumerate(files, start=1):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime))
        print(f" {i:2d}) {p.name}  [{ts}]")
    sel = input(f"{prompt} [1-{len(files)}]: ").strip()
    try:
        idx = int(sel)
        if 1 <= idx <= len(files):
            return files[idx-1]
    except Exception:
        pass
    warn("Invalid selection.")
    return None

# ---------- Export helpers ----------

def _ts() -> str:
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

def _md_escape(s: str) -> str:
    # very light escape for MD tables
    return s.replace("|", r"\|")

def build_markdown(r: dict) -> str:
    target = r.get("target","")
    pages  = r.get("crawled_pages",0)
    forms  = r.get("discovered_forms",0)
    dur    = r.get("duration_seconds")
    findings = r.get("findings", [])
    buckets = _bucketize(findings)

    lines = []
    lines.append("# TSA Web Tester Report")
    lines.append(f"**Target:** {target}")
    if dur is not None:
        lines.append(f"**Pages:** {pages}  **Forms:** {forms} • Duration: {dur:.1f}s")
    else:
        lines.append(f"**Pages:** {pages}  **Forms:** {forms}")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- HIGH: {len(buckets['HIGH'])}")
    lines.append(f"- MEDIUM: {len(buckets['MEDIUM'])}")
    lines.append(f"- INFO/LOW: {len(buckets['INFO'])}")
    lines.append("")

    def section(name: str, items: List[dict]):
        lines.append(f"## {name} Severity Findings")
        if not items:
            lines.append("_None_")
            lines.append("")
            return
        lines.append("| Severity | Category | URL | Param | Evidence |")
        lines.append("|---|---|---|---|---|")
        for f in items:
            sev = _md_escape(str(f.get("severity","")))
            cat = _md_escape(str(f.get("category","")))
            url = _md_escape(str(f.get("url","")))
            prm = _md_escape(str(f.get("param","-")))
            ev  = _md_escape(str(f.get("evidence","")))
            lines.append(f"| {sev} | {cat} | {url} | {prm} | {ev} |")
        lines.append("")

    section("High", buckets["HIGH"])
    section("Medium", buckets["MEDIUM"])
    section("Informational / Low", buckets["INFO"])

    # Crawled pages snapshot (optional)
    pages_list = r.get("crawled_pages_top", r.get("crawled_pages_list", []))
    if pages_list:
        lines.append("## Top Crawled Pages")
        for u in pages_list[:25]:
            lines.append(f"- {u}")
        lines.append("")

    lines.append("---")
    lines.append("_Generated by TSA Web Tester terminal UI_")
    return "\n".join(lines)

def export_markdown(r: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"report_{_ts()}.md"
    p.write_text(build_markdown(r), encoding="utf-8")
    ok(f"Markdown saved: {p}")
    return p

def export_csv(r: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"report_{_ts()}.csv"
    fields = ["Target","Severity","Category","URL","Param","Evidence","Timestamp","Pages","Forms"]
    target = r.get("target","")
    pages  = r.get("crawled_pages",0)
    forms  = r.get("discovered_forms",0)

    with p.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
        w.writerow(fields)
        for it in r.get("findings", []):
            w.writerow([
                target,
                it.get("severity",""),
                it.get("category",""),
                it.get("url",""),
                it.get("param","-"),
                it.get("evidence",""),
                r.get("finished_at",""),
                pages,
                forms,
            ])
    ok(f"CSV saved: {p}")
    return p

def _build_html_from_md(md_text: str) -> str:
    # Minimal CSS for nice print/PDF
    css = """
    <style>
      body{font-family:Inter,Segoe UI,Arial,sans-serif;margin:28px;color:#e6e6e6;background:#0f172a}
      h1{font-size:28px;margin:0 0 10px}
      h2{margin-top:28px}
      code,pre{background:#0b1022;padding:2px 4px;border-radius:4px}
      table{width:100%;border-collapse:collapse;margin-top:10px;font-size:14px}
      th,td{border:1px solid #23304f;padding:8px;vertical-align:top}
      th{background:#0b1022}
      a{color:#93c5fd}
      .muted{color:#9aa4b2}
      hr{border:0;border-top:1px solid #23304f;margin:24px 0}
    </style>
    """
    # super-light MD → HTML for common parts (no external deps)
    import html
    lines = []
    for raw in md_text.splitlines():
        line = raw.strip("\n")
        if line.startswith("# "):
            lines.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            lines.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line == "---":
            lines.append("<hr/>")
        elif line.startswith("- "):
            lines.append(f"<div>• {html.escape(line[2:])}</div>")
        elif "|" in line and line.count("|") >= 2:
            # crude table detection
            if line.startswith("|---"):
                continue
            cells = [html.escape(c.strip()) for c in line.strip("|").split("|")]
            if not lines or not lines[-1].startswith("<table"):
                lines.append("<table><tbody>")
            lines.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
            # close table when we hit a non-table line later; do this lazily
        else:
            # close table if last open
            if lines and lines[-1].startswith("<tr>"):
                # find start and ensure closing
                if "<table><tbody>" in "".join(lines[-20:]):
                    lines.append("</tbody></table>")
            if line:
                lines.append(f"<div>{html.escape(line)}</div>")
            else:
                lines.append("<div style='height:8px'></div>")

    if lines and lines[-1].startswith("<tr>"):
        lines.append("</tbody></table>")

    return f"<!doctype html><html><head><meta charset='utf-8'><title>TSA Web Tester Report</title>{css}</head><body>" + "\n".join(lines) + "</body></html>"

def export_pdf_or_html(r: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = build_markdown(r)
    html_str = _build_html_from_md(md)
    pdf_path = out_dir / f"report_{_ts()}.pdf"
    if _WHTML is not None:
        try:
            _WHTML(string=html_str).write_pdf(str(pdf_path))
            ok(f"PDF saved: {pdf_path}")
            return pdf_path
        except Exception as e:
            warn(f"PDF render failed ({e}); writing HTML instead.")
    # fallback: write HTML you can print to PDF
    html_path = out_dir / f"report_{_ts()}.html"
    html_path.write_text(html_str, encoding="utf-8")
    warn(f"No PDF engine detected. Wrote printable HTML instead: {html_path}")
    return html_path

def export_bundle(json_path: Path):
    rpt = load_report(json_path)
    if not rpt:
        err("Could not load report.")
        return
    out = json_path.parent  # save next to reports
    md = export_markdown(rpt, out)
    csvp = export_csv(rpt, out)
    pdfp = export_pdf_or_html(rpt, out)
    info("\nBundle exported:")
    print(" -", md.name)
    print(" -", csvp.name)
    print(" -", pdfp.name)

# ---------- Advanced Scan (unchanged logic except prompt text) ----------

def _safe_int(val: str, default: int) -> int:
    try:
        return int(val)
    except Exception:
        return default

def _bool_yn(prompt: str, default: bool) -> bool:
    raw = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if raw == "": return default
    return raw in ("y","yes","1","true","t")

def _maybe_path_input(prompt: str) -> Optional[Path]:
    raw = input(prompt).strip()
    if not raw: return None
    p = Path(raw).expanduser()
    return p if p.exists() else None

def _read_payload_file_lines(p: Path, max_lines: int = 8000) -> List[str]:
    out: List[str] = []
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                if i > max_lines: break
                s = line.strip()
                if not s: continue
                if s.startswith("#") or s.startswith("//"): continue
                out.append(s)
    except Exception as e:
        warn(f"Could not read payload file {p}: {e}")
    return out

def _load_base_config() -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "scanner": {
            "user_agent": "MiniOWASP/1.0 (+https://github.com/example)",
            "timeout_seconds": 15,
            "verify_ssl": True,
            "follow_redirects": True,
            "follow_redirect_hosts": False,
            "same_host_only": True,
            "max_depth": 2,
            "max_pages": 100,
            "delay_ms": 250,
            "retries": 1,
            "backoff_factor": 0.25,
            "allowed_hosts": [],
        },
        "exclusions": {
            "domains": [],
            "paths": [".jpg",".jpeg",".png",".gif",".css",".woff",".woff2",".ttf",".svg",".ico",".pdf",".zip","mailto:","javascript:"]
        },
        "payloads": {
            "xss_reflected": ["<svg onload=alert(1)>", "\"><img src=x onerror=alert(1)>", "'\"><script>alert(1)</script>"],
            "sqli_basic": ["' OR '1'='1", "' UNION SELECT 1--", "\" OR 1=1--"],
        },
        "headers_required": [
            "Content-Security-Policy","X-Content-Type-Options","X-Frame-Options","Referrer-Policy","Strict-Transport-Security",
        ],
        "javascript": {"enabled": False,"headless": True,"nav_timeout_ms": 12000,"run_timeout_ms": 4000,"max_body_chars": 200000},
        "report": {"json": True, "html": True, "save_hashes": False},
        "safety": {"allow_global_scan_flag": False},
    }
    if DEFAULT_CFG.exists() and yaml is not None:
        try:
            user = yaml.safe_load(DEFAULT_CFG.read_text(encoding="utf-8")) or {}
            for k, v in user.items():
                base[k] = v
        except Exception as e:
            warn(f"Could not read base config {DEFAULT_CFG}: {e}")
    return base

def _write_temp_config(cfg: Dict[str, Any]) -> Path:
    tf = tempfile.NamedTemporaryFile(prefix="adv_cfg_", suffix=".yaml", delete=False)
    tf_path = Path(tf.name)
    tf.close()
    if yaml is None:
        tf_path.write_text("# temp config\n" + json.dumps(cfg, indent=2), encoding="utf-8")
    else:
        tf_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    return tf_path

def do_advanced_scan():
    if yaml is None:
        err("Advanced Scan needs PyYAML. Install with: pip install pyyaml")
        return
    url = input("Target URL (e.g., http://testphp.vulnweb.com/): ").strip()
    if not url:
        err("No URL provided."); return

    base = _load_base_config()
    scn = base.setdefault("scanner", {})

    print("\n--- Scanner options (press Enter to keep defaults) ---")
    scn["max_depth"] = _safe_int(input(f"max_depth [{scn.get('max_depth',2)}]: "), scn.get("max_depth",2))
    scn["max_pages"] = _safe_int(input(f"max_pages [{scn.get('max_pages',100)}]: "), scn.get("max_pages",100))
    scn["delay_ms"] = _safe_int(input(f"delay_ms [{scn.get('delay_ms',250)}]: "), scn.get("delay_ms",250))
    scn["same_host_only"] = _bool_yn("same_host_only", bool(scn.get("same_host_only", True)))
    scn["follow_redirects"] = _bool_yn("follow_redirects", bool(scn.get("follow_redirects", True)))
    scn["follow_redirect_hosts"] = _bool_yn("follow_redirect_hosts", bool(scn.get("follow_redirect_hosts", False)))

    raw_hosts = input("allowed_hosts (comma-separated, empty=none) []: ").strip()
    if raw_hosts:
        scn["allowed_hosts"] = [h.strip() for h in raw_hosts.split(",") if h.strip()]

    print("\n--- JavaScript rendering (optional) ---")
    js = base.setdefault("javascript", {})
    js["enabled"] = _bool_yn("javascript.enabled", bool(js.get("enabled", False)))
    if js["enabled"]:
        js["headless"] = _bool_yn("javascript.headless", bool(js.get("headless", True)))
        js["nav_timeout_ms"] = _safe_int(input(f"javascript.nav_timeout_ms [{js.get('nav_timeout_ms',12000)}]: "), js.get("nav_timeout_ms",12000))
        js["run_timeout_ms"] = _safe_int(input(f"javascript.run_timeout_ms [{js.get('run_timeout_ms',4000)}]: "), js.get("run_timeout_ms",4000))
        js["max_body_chars"] = _safe_int(input(f"javascript.max_body_chars [{js.get('max_body_chars',200000)}]: "), js.get("max_body_chars",200000))

    print("\n--- Modules selection ---")
    use_headers = _bool_yn("Include Headers check?", True)
    use_xss     = _bool_yn("Include XSS tests?", True)
    use_sqli    = _bool_yn("Include SQLi tests?", True)

    if not use_headers:
        base["headers_required"] = []

    print("\n--- Optional custom payload files ---")
    xss_path = _maybe_path_input("Path to XSS payload file (empty=skip): ")
    sqli_path = _maybe_path_input("Path to SQLi payload file (empty=skip): ")

    plds = base.setdefault("payloads", {})

    if use_xss:
        xss_list = plds.get("xss_reflected", [])
        if xss_path:
            extra = _read_payload_file_lines(xss_path, max_lines=8000)
            if extra:
                xss_list = list(dict.fromkeys(xss_list + extra))
                ok(f"Loaded {len(extra)} XSS payloads from {xss_path}")
        plds["xss_reflected"] = xss_list
    else:
        plds["xss_reflected"] = []

    if use_sqli:
        sqli_list = plds.get("sqli_basic", [])
        if sqli_path:
            extra = _read_payload_file_lines(sqli_path, max_lines=8000)
            if extra:
                sqli_list = list(dict.fromkeys(sqli_list + extra))
                ok(f"Loaded {len(extra)} SQLi payloads from {sqli_path}")
        plds["sqli_basic"] = sqli_list
    else:
        plds["sqli_basic"] = []

    temp_cfg = _write_temp_config(base)
    info(f"\nWrote temporary advanced config: {temp_cfg}")

    debug = _bool_yn("Enable --debug?", False)
    details = _bool_yn("Show --details in console output?", True)

    json_p, html_p, code = run_cli_scan(url, config=temp_cfg, out_dir=REPORTS_DIR, debug=debug, details=details)
    if code != 0:
        err(f"cli.py exited with {code}")
        return
    if json_p and json_p.exists():
        ok(f"\nSaved JSON: {json_p}")
        rpt = load_report(json_p)
        if rpt:
            info("Summary:")
            print(" ", summarize_report(rpt))
            pretty_print_findings_by_severity(rpt, limit_per_bucket=50)
        else:
            warn("Could not parse the new report.")

# ---------- Simple actions ----------

def do_start_scan():
    url = input("Target URL (e.g., http://testphp.vulnweb.com/): ").strip()
    if not url:
        err("No URL provided."); return
    use_cfg = input(f"Use config [{DEFAULT_CFG}] ? [Y/n]: ").strip().lower()
    cfg = DEFAULT_CFG if use_cfg in ("","y","yes") and DEFAULT_CFG.exists() else None
    debug = input("Enable --debug? [y/N]: ").strip().lower() in ("y","yes")
    details = input("Show --details in console? [y/N]: ").strip().lower() in ("y","yes")
    json_p, html_p, code = run_cli_scan(url, config=cfg, out_dir=REPORTS_DIR, debug=debug, details=details)
    if code != 0:
        err(f"cli.py exited with {code}"); return
    if json_p and json_p.exists():
        ok(f"\nSaved JSON: {json_p}")
        rpt = load_report(json_p)
        if rpt:
            info("Summary:"); print(" ", summarize_report(rpt))
            pretty_print_findings_by_severity(rpt, limit_per_bucket=50)
        else:
            warn("Could not parse the new report.")
    else:
        warn("Could not detect saved report paths in output. Check above logs.")

def do_list_reports():
    files = list_report_files(50)
    if not files:
        warn("No reports yet."); return
    rows = []
    for p in files:
        rpt = load_report(p)
        summary = summarize_report(rpt) if rpt else "(unreadable)"
        rows.append([p.name, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime)), summary])
    print("\n" + tabulate(rows, headers=["Report JSON","Modified","Summary"], tablefmt="psql"))

def do_view_report():
    p = choose_report_path("View which report")
    if not p: return
    rpt = load_report(p)
    if not rpt: return
    info(f"\nTarget: {rpt.get('target')} • Pages: {rpt.get('crawled_pages')} • Forms: {rpt.get('discovered_forms')}")
    print(" " + summarize_report(rpt))
    pretty_print_findings_by_severity(rpt, limit_per_bucket=50)

def do_open_or_export():
    p = choose_report_path("Open/Export for which report")
    if not p: return
    rpt = load_report(p)
    if not rpt: return
    print("\n[5] Open HTML / Export")
    print("  a) Open HTML in browser")
    print("  b) Export Markdown (.md)")
    print("  c) Export CSV (.csv)")
    print("  d) Export PDF (.pdf)  (uses WeasyPrint if present; else printable HTML)")
    print("  e) Export Bundle (MD + CSV + PDF/HTML)")
    sel = input("Choose [a-e]: ").strip().lower()
    if sel == "a":
        open_html_for_json(p)
    elif sel == "b":
        export_markdown(rpt, p.parent)
    elif sel == "c":
        export_csv(rpt, p.parent)
    elif sel == "d":
        export_pdf_or_html(rpt, p.parent)
    elif sel == "e":
        export_bundle(p)
    else:
        print("Cancelled.")

def do_show_raw_json():
    p = choose_report_path("Show raw JSON for which report")
    if not p: return
    try: print("\n" + p.read_text(encoding="utf-8"))
    except Exception as e: err(f"Failed: {e}")

def do_delete_report():
    p = choose_report_path("Delete which report")
    if not p: return
    html_p = p.with_suffix(".html")
    confirm = input(f"Delete {p.name} and {html_p.name if html_p.exists() else '(no html)'}? [y/N]: ").strip().lower()
    if confirm not in ("y","yes"): print("Cancelled."); return
    try:
        p.unlink(missing_ok=True); html_p.unlink(missing_ok=True)
        ok("Deleted.")
    except Exception as e: err(f"Delete failed: {e}")

def do_open_latest_html():
    p = latest_report_json()
    if not p:
        warn("No reports yet."); return
    open_html_for_json(p)

# ---------- Menu (8 items as requested) ----------

def menu():
    while True:
        print()
        info("=== MAIN MENU ===")
        print("1) Quick scan")
        print("2) Advanced scan (override config, custom payloads)")
        print("3) List latest reports")
        print("4) View a report in terminal (JSON)")
        print("5) Open HTML / Export (MD/CSV/PDF/Bundle)")
        print("6) Show raw JSON of a report")
        print("7) Delete a report")
        print("8) Open latest HTML report")
        print("0) Exit")
        choice = input("\nSelect: ").strip()
        if choice == "1":   do_start_scan()
        elif choice == "2": do_advanced_scan()
        elif choice == "3": do_list_reports()
        elif choice == "4": do_view_report()
        elif choice == "5": do_open_or_export()
        elif choice == "6": do_show_raw_json()
        elif choice == "7": do_delete_report()
        elif choice == "8": do_open_latest_html()
        elif choice == "0": print("Bye."); break
        else: print("Unknown option.")

def main():
    if not ensure_paths(): sys.exit(1)
    try: menu()
    except KeyboardInterrupt: print("\nBye.")

if __name__ == "__main__":
    main()

