#!/usr/bin/env python3
"""
CLI entrypoint for the Mini-OWASP scanner (terminal-first).
Uses the modular core package in `core/`.

Usage:
  python cli.py --url http://example.com --config config.yaml --out reports --details --debug
"""

from __future__ import annotations
import argparse
import logging
import sys
from collections import defaultdict
import time

from colorama import Fore, Style, init as colorama_init

# Import core functions (adjust package import path if you used a different folder)
from core.utils import load_config
from core.wvscanner_core import run_scan, save_report, ScanResult, Finding

# Initialize colorama
colorama_init(autoreset=True)

# Logging config (default INFO; --debug will set DEBUG)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("mini-owasp-cli")


def parse_args():
    ap = argparse.ArgumentParser(description="Mini OWASP Web Vulnerability Scanner (CLI)")
    ap.add_argument("--url", required=True, help="Target URL (e.g., http://testphp.vulnweb.com/)")
    ap.add_argument("--config", default="config.yaml", help="Config YAML path")
    ap.add_argument("--out", default="reports", help="Output directory for reports")
    ap.add_argument("--debug", action="store_true", help="Enable DEBUG logging")
    ap.add_argument("--details", action="store_true", help="Show detailed findings (pages + per-category lists)")
    return ap.parse_args()


def print_colored_summary(result: ScanResult):
    high = [f for f in result.findings if f.severity == "HIGH"]
    med = [f for f in result.findings if f.severity == "MEDIUM"]
    info = [f for f in result.findings if f.severity in ("LOW", "INFO")]

    print()
    print(Fore.CYAN + f"=== Scan Summary for {result.target} ===" + Style.RESET_ALL)
    print(f"Pages crawled: {Fore.YELLOW}{result.crawled_pages}{Style.RESET_ALL} | Forms: {Fore.YELLOW}{result.discovered_forms}{Style.RESET_ALL}")
    print(f"{Fore.RED}HIGH:{Style.RESET_ALL} {len(high)}  {Fore.YELLOW}MEDIUM:{Style.RESET_ALL} {len(med)}  {Fore.BLUE}INFO:{Style.RESET_ALL} {len(info)}")
    print()

    by_cat = defaultdict(list)
    for f in result.findings:
        by_cat[f.category].append(f)

    if not result.findings:
        print(Fore.GREEN + "No findings — nice! 🎉" + Style.RESET_ALL)
        return

    print(Fore.MAGENTA + "Findings by category:" + Style.RESET_ALL)
    for cat, items in sorted(by_cat.items(), key=lambda x: (-len(x[1]), x[0])):
        color = Fore.YELLOW if any(i.severity == "MEDIUM" for i in items) else (Fore.RED if any(i.severity == "HIGH" for i in items) else Fore.CYAN)
        print(f"  {color}{cat}{Style.RESET_ALL}: {len(items)}")
    print()


def print_pages_and_forms(result: ScanResult, max_pages_show=50):
    print(Fore.BLUE + "Crawled pages (top):" + Style.RESET_ALL)
    for p in result.pages[:max_pages_show]:
        print("  -", p)
    if len(result.pages) > max_pages_show:
        print(f"  ... ({len(result.pages) - max_pages_show} more pages)")

    print()
    print(Fore.BLUE + "Forms discovered (page -> inputs):" + Style.RESET_ALL)
    if not result.forms:
        print("  (no HTML/GET forms discovered by crawler)")
    else:
        for page, forms in result.forms.items():
            print(f"  {page} -> {len(forms)} form(s)")
            for fi, form in enumerate(forms, start=1):
                inputs = ", ".join(form['inputs'].keys()) if form.get('inputs') else "(no inputs)"
                print(f"    [{fi}] {form['method'].upper()} {form['action']}   inputs: {inputs}")
    print()


def print_detailed(result: ScanResult, max_show_per_cat=20):
    if not result.findings:
        return

    by_cat = defaultdict(list)
    for f in result.findings:
        by_cat[f.category].append(f)

    for cat in sorted(by_cat.keys()):
        items = by_cat[cat]
        print(Fore.MAGENTA + f"--- {cat} ({len(items)}) ---" + Style.RESET_ALL)
        items_sorted = sorted(items, key=lambda x: ("0" if x.severity == "HIGH" else "1" if x.severity == "MEDIUM" else "2", x.url))
        for idx, f in enumerate(items_sorted[:max_show_per_cat], start=1):
            sev_color = Fore.RED if f.severity == "HIGH" else (Fore.YELLOW if f.severity == "MEDIUM" else Fore.CYAN)
            print(f" {sev_color}[{f.severity}]{Style.RESET_ALL} {f.url}  param={Fore.GREEN}{f.param}{Style.RESET_ALL}")
            print(f"    evidence: {f.evidence}")
        if len(items) > max_show_per_cat:
            print(f"    ... ({len(items) - max_show_per_cat} more findings in category {cat})")
        print()


def main():
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        log.debug("Debug logging enabled")

    try:
        cfg = load_config(args.config)
    except Exception as e:
        log.error("Failed to load config %s: %s", args.config, e)
        sys.exit(1)

    print(Fore.GREEN + f"[+] Starting scan for {args.url} (config={args.config})" + Style.RESET_ALL)
    start_time = time.time()
    result = run_scan(args.url, cfg)
    end_time = time.time()
    print(Fore.GREEN + f"[+] Scan finished in {end_time - start_time:.1f}s" + Style.RESET_ALL)

    print_colored_summary(result)

    if args.details:
        print_pages_and_forms(result)
        print_detailed(result, max_show_per_cat=25)

    json_path, html_path = save_report(result, args.out)
    print(Fore.MAGENTA + f"[report] Reports saved: {json_path} | {html_path}" + Style.RESET_ALL)


if __name__ == "__main__":
    main()
