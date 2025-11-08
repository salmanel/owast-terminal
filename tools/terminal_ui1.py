#!/usr/bin/env python3
"""
OWASP Tester – Terminal Interface
- Compact Star-Wars style crawl banner: "TSA WEB TESTER"
- Disable animation with env var: TUI_NO_ANIM=1
- Severity-first printing: HIGH -> MEDIUM -> INFO
- Same features: start scan, list/view/open/delete reports, open latest HTML
"""

from __future__ import annotations

import os, sys, json, time, subprocess, webbrowser, re, shutil
from pathlib import Path
from typing import Optional, Tuple, List
from colorama import init as colorama_init, Fore, Style
from tabulate import tabulate

colorama_init(autoreset=True)

# ---------------- PATHS ----------------
REPO_ROOT   = Path(__file__).resolve().parent.parent
CLI_PATH    = REPO_ROOT / "cli.py"
DEFAULT_CFG = REPO_ROOT / "config.yaml"
REPORTS_DIR = REPO_ROOT / "reports"
PYTHON      = sys.executable
# --------------------------------------

def info(msg: str): print(Fore.CYAN + msg + Style.RESET_ALL)
def ok(msg: str):   print(Fore.GREEN + msg + Style.RESET_ALL)
def warn(msg: str): print(Fore.YELLOW + msg + Style.RESET_ALL)
def err(msg: str):  print(Fore.RED + msg + Style.RESET_ALL)

# ========= STAR-WARS STYLE CRAWL BANNER =========
def _term_width() -> int:
    try:
        return shutil.get_terminal_size((100, 24)).columns
    except Exception:
        return 100

def _space_text(text: str, spaces: int) -> str:
    if spaces <= 0:
        return text
    return (" " * spaces).join(list(text))

def star_wars_crawl(text: str = "TSA WEB TESTER", lines: int = 14, anim: bool = True, delay: float = 0.08):
    """
    Prints a short 'backward' crawl: small & far at top -> large & near at bottom.
    Uses spacing + indentation + dimming to fake perspective.
    """
    text = text.upper()
    width = _term_width()
    # Create the 'depth' lines top->bottom (far->near)
    block: List[str] = []
    for i in range(lines):
        frac = i / max(1, lines - 1)  # 0..1
        # perspective: more indent at top, less at bottom
        indent = int((1.0 - frac) * (width * 0.20))  # far lines shifted right
        # spacing: small at top, more at bottom
        spacing = max(0, int(frac * 3))
        # brightness: dim at top, bright at bottom
        if frac < 0.33:
            col = Style.DIM + Fore.YELLOW
        elif frac < 0.66:
            col = Fore.YELLOW
        else:
            col = Style.BRIGHT + Fore.YELLOW

        line_text = _space_text(text, spacing)
        # softly center the line after indent
        content = (" " * indent) + line_text
        # hard trim to terminal width to avoid wrap
        content = content[:width]
        block.append(col + content + Style.RESET_ALL)

    # If no animation, print once and return
    if not anim:
        print()
        for ln in block:
            print(ln)
        print()
        return

    # Animate: scroll the block upward a few steps
    print()
    # Build scroll frames by prefixing a few empty lines and then revealing block
    pad_top = lines  # start off-screen a bit
    frames = []
    for offset in range(pad_top + lines + 3):
        start = max(0, pad_top - offset)
        frame_lines = [""] * start + block[: min(offset, len(block))]
        frames.append(frame_lines)

    # Render frames
    for fr in frames:
        # don't hard-clear terminal; just print enough newlines for a soft scroll effect
        print("\n" * 2, end="")
        for ln in fr:
            print(ln)
        time.sleep(delay)
    print()

# ======================================

def ensure_paths() -> bool:
    # Show crawl unless disabled
    if os.environ.get("TUI_NO_ANIM", "0") not in ("1", "true", "TRUE", "yes", "YES"):
        try:
            star_wars_crawl("TSA WEB TESTER", lines=14, anim=True, delay=0.06)
        except Exception:
            # fallback static
            star_wars_crawl("TSA WEB TESTER", lines=10, anim=False)
    else:
        star_wars_crawl("TSA WEB TESTER", lines=10, anim=False)

    ok("Terminal Interface ready")
    print(f"Project root: {REPO_ROOT}")
    if not CLI_PATH.exists():
        err(f"cli.py not found at: {CLI_PATH}")
        print("Expected at project root alongside: config.yaml, core/, reports/")
        return False
    if not DEFAULT_CFG.exists():
        warn(f"config.yaml not found at: {DEFAULT_CFG} (you can still pass --config in scans)")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return True

REPORTS_LINE = re.compile(r"Reports saved:\s*(?P<json>[^|]+\.json)\s*\|\s*(?P<html>.+\.html)", re.I)

def run_cli_scan(url: str, *, config: Optional[Path]=None, out_dir: Optional[Path]=None, debug=False, details=False) -> Tuple[Optional[Path], Optional[Path], int]:
    args = [PYTHON, str(CLI_PATH), "--url", url]
    if config:   args += ["--config", str(config)]
    if out_dir:  args += ["--out", str(out_dir)]
    if debug:    args += ["--debug"]
    if details:  args += ["--details"]

    print(Fore.MAGENTA + "\n> " + " ".join(map(str, args)) + Style.RESET_ALL)
    json_path = html_path = None

    proc = subprocess.Popen(args, cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
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
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    med  = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    info_n = sum(1 for f in findings if f.get("severity") in ("LOW","INFO"))
    return f"Pages: {r.get('crawled_pages', 0)} | Forms: {r.get('discovered_forms', 0)} | HIGH: {high} | MEDIUM: {med} | INFO: {info_n}"

def pretty_print_findings_by_severity(r: dict, limit_per_bucket: int = 100):
    """
    Print findings grouped by severity with strict priority:
    HIGH (red) → MEDIUM (yellow) → INFO/LOW (cyan)
    """
    findings = r.get("findings", [])
    if not findings:
        ok("No findings 🎉")
        return

    buckets = {"HIGH": [], "MEDIUM": [], "INFO": []}
    for f in findings:
        sev = (f.get("severity") or "").upper()
        if sev == "HIGH":
            buckets["HIGH"].append(f)
        elif sev == "MEDIUM":
            buckets["MEDIUM"].append(f)
        else:
            buckets["INFO"].append(f)

    def emit(name: str, color, items: List[dict]):
        if not items:
            return
        print(color + f"\n=== {name} ({len(items)}) ===" + Style.RESET_ALL)
        rows = [[it.get("severity",""), it.get("category",""), it.get("url",""), it.get("param",""), it.get("evidence","")] for it in items[:limit_per_bucket]]
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
    files = list_report_files()
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

# -------- MENU ACTIONS --------
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

def do_open_html():
    p = choose_report_path("Open HTML for which report")
    if not p: return
    open_html_for_json(p)

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

# -------- MENU LOOP --------
def menu():
    while True:
        print()
        info("=== MAIN MENU ===")
        print("1) Start new scan")
        print("2) List latest reports")
        print("3) View a report in terminal (JSON)")
        print("4) Open HTML report in browser")
        print("5) Show raw JSON of a report")
        print("6) Delete a report")
        print("7) Open latest HTML report")
        print("0) Exit")
        choice = input("\nSelect: ").strip()
        if choice == "1":   do_start_scan()
        elif choice == "2": do_list_reports()
        elif choice == "3": do_view_report()
        elif choice == "4": do_open_html()
        elif choice == "5": do_show_raw_json()
        elif choice == "6": do_delete_report()
        elif choice == "7": do_open_latest_html()
        elif choice == "0": print("Bye."); break
        else: print("Unknown option.")

def main():
    if not ensure_paths(): sys.exit(1)
    try: menu()
    except KeyboardInterrupt: print("\nBye.")

if __name__ == "__main__":
    main()
