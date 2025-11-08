#!/usr/bin/env python3
"""
Mini OWASP Web Scanner (Core) — v1.2 (with incremental reporter + pretty HTML)
- Crawler with allowlist / excludes / redirect control
- Modules: reflected XSS (basic), SQLi (basic), Security headers
- Incremental JSONL reporter (writes findings as they appear)
- Reporter: JSON + Pretty HTML (final)
NOTE: For educational use on assets you own / are allowed to test.
"""

from __future__ import annotations

import os
import re
import time
import json
import html
import queue
import logging
import uuid
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple, Any
import urllib.parse as urlparse
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings

# local incremental reporter
from core.reporters.incremental_jsonl import IncrementalJSONLReporter

# Silence noisy bs4 XML warning when pages look XML-ish but parsed as HTML.
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

log = logging.getLogger("wvscanner_core")

# -------------------------
# Data models
# -------------------------
@dataclass
class Finding:
    severity: str    # "HIGH" / "MEDIUM" / "LOW" / "INFO"
    category: str    # "XSS", "SQLi", "Headers", etc.
    url: str
    param: str       # GET key or form input name; "-" if not applicable
    evidence: str

@dataclass
class ScanResult:
    target: str
    pages: List[str]
    forms: Dict[str, List[Dict[str, str]]]
    crawled_pages: int
    discovered_forms: int
    findings: List[Finding]
    started_at: float
    finished_at: float

# -------------------------
# Utilities
# -------------------------
def norm_url(u: str) -> str:
    try:
        parsed = urlparse.urlsplit(u)
        if not parsed.scheme:
            return "http://" + u
        return u
    except Exception:
        return u

def same_host(url_a: str, url_b: str) -> bool:
    try:
        a = urlparse.urlsplit(url_a).netloc
        b = urlparse.urlsplit(url_b).netloc
        return a.lower() == b.lower()
    except Exception:
        return False

def host_in_allowed(host: str, allowed_hosts: List[str]) -> bool:
    if not allowed_hosts:
        return True
    host = (host or "").lower()
    for allowed in allowed_hosts:
        allowed = allowed.lower()
        if host == allowed or (allowed and host.endswith("." + allowed)):
            return True
    return False

def should_skip(href: str, excludes_paths: List[str], exclude_domains: List[str]) -> bool:
    try:
        host = urlparse.urlsplit(href).netloc.lower()
    except Exception:
        host = ""
    # Domain excludes
    if host and any(host == d or host.endswith("." + d) for d in exclude_domains):
        return True
    # Path substrings
    href_l = href.lower()
    return any(e in href_l for e in excludes_paths)

def make_session(user_agent: str,
                 follow_redirects: bool,
                 timeout: int,
                 verify_ssl: bool = True,
                 retries: int = 2,
                 backoff_factor: float = 0.4) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent})
    s.verify = verify_ssl
    s.allow_redirects = follow_redirects
    # custom attribute used by our code
    s.request_timeout = timeout

    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        redirect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "HEAD", "OPTIONS"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

# -------------------------
# Incremental scan context
# -------------------------
class ScanContext:
    def __init__(self, out_dir: str, target: str):
        self.scan_id = f"scan_{time.strftime('%Y%m%d-%H%M%S')}_{uuid.uuid4().hex[:8]}"
        self.out_dir = Path(out_dir)
        self.target = target
        self.seen: Set[Tuple[Any, ...]] = set()
        self.reporter = IncrementalJSONLReporter(self.out_dir, self.scan_id)
        self.reporter.set_target(target)

    def add(self, f: Finding) -> bool:
        """Add finding if not seen. Return True if new, False if duplicate."""
        key = (f.severity or "", f.category or "", f.url or "", f.param or "", hash(f.evidence or ""))
        if key in self.seen:
            return False
        self.seen.add(key)
        try:
            self.reporter.add_finding(f)
        except Exception:
            log.exception("Failed to add finding to incremental reporter")
        return True

    def update_progress(self, pages: int, forms: int):
        try:
            self.reporter.update_progress(pages, forms)
        except Exception:
            pass

    def close(self):
        try:
            self.reporter.close()
        except Exception:
            pass

# -------------------------
# Crawler
# -------------------------
def crawl(start_url: str,
          session: requests.Session,
          *,
          max_depth: int,
          same_host_only: bool,
          excludes_paths: List[str],
          exclude_domains: List[str],
          follow_redirect_hosts: bool,
          allowed_hosts: List[str],
          max_pages: int,
          delay_ms: int) -> Tuple[List[str], Dict[str, List[Dict[str, str]]]]:
    """
    Returns:
      pages: list of unique page URLs visited
      forms: mapping URL -> list of forms (each: {action, method, inputs: dict})
    """
    pages: List[str] = []
    forms: Dict[str, List[Dict[str, str]]] = {}
    visited: Set[str] = set()

    start_url = norm_url(start_url)
    start_host = urlparse.urlsplit(start_url).netloc.lower()

    q: queue.Queue = queue.Queue()
    q.put((start_url, 0))

    while not q.empty():
        url, depth = q.get()
        if url in visited or depth > max_depth:
            continue

        try:
            resp = session.get(url, timeout=session.request_timeout, allow_redirects=True)
            effective_url = resp.url
        except Exception as e:
            log.warning("Fetch failed for %s: %s", url, e.__class__.__name__)
            continue

        requested_host = urlparse.urlsplit(url).netloc.lower()
        effective_host = urlparse.urlsplit(effective_url).netloc.lower()

        if effective_host != requested_host:
            if not follow_redirect_hosts:
                log.info("Skipping %s -> redirected to another host %s (enable follow_redirect_hosts to follow)", url, effective_host)
                visited.add(url)
                continue
            else:
                log.info("Following redirect %s -> %s", url, effective_url)
                url = effective_url

        # Host scoping
        this_host = urlparse.urlsplit(url).netloc.lower()
        if same_host_only and this_host != start_host:
            log.debug("Skip %s (outside start host %s)", url, start_host)
            visited.add(url)
            continue

        # Host allowlist
        if not host_in_allowed(this_host, allowed_hosts):
            log.debug("Skip %s (host %s not allowed)", url, this_host)
            visited.add(url)
            continue

        # avoid reprocessing
        if url in visited:
            continue
        visited.add(url)
        pages.append(url)

        # safety cap
        if max_pages and len(pages) >= max_pages:
            log.info("Reached max_pages=%d, stopping crawl", max_pages)
            break

        # Parse
        soup = BeautifulSoup(resp.text, "lxml")

        # collect forms
        page_forms = []
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            action = form.get("action") or url
            action = urlparse.urljoin(url, action)
            inputs = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                value = inp.get("value") or ""
                inputs[name] = value
            page_forms.append({"action": action, "method": method, "inputs": inputs})
        if page_forms:
            forms[url] = page_forms

        # enqueue links
        for a in soup.find_all("a", href=True):
            href = urlparse.urljoin(url, a["href"])
            if should_skip(href, excludes_paths, exclude_domains):
                continue
            link_host = urlparse.urlsplit(href).netloc.lower()
            if not host_in_allowed(link_host, allowed_hosts):
                continue
            if same_host_only and not same_host(start_url, href):
                continue
            if href not in visited:
                q.put((href, depth + 1))

        if delay_ms:
            time.sleep(delay_ms / 1000.0)

    return pages, forms

# -------------------------
# Modules: XSS (reflected), SQLi (basic), Headers
# -------------------------
def test_reflected_xss(session: requests.Session, url: str, param: str, payloads: List[str]) -> Optional[Finding]:
    for p in payloads:
        try:
            parsed = urlparse.urlsplit(url)
            qs = dict(urlparse.parse_qsl(parsed.query, keep_blank_values=True))
            qs[param] = p
            url_mod = urlparse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlparse.urlencode(qs), parsed.fragment))
            r = session.get(url_mod, timeout=session.request_timeout)
            if p in r.text:
                return Finding("HIGH", "XSS", url_mod, param, f"Reflected payload: {p}")
        except Exception:
            continue
    return None

def test_sqli_basic(session: requests.Session, url: str, param: str, payloads: List[str]) -> Optional[Finding]:
    error_signatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "pg_query():",
        "mysql_fetch_array()",
        "sqlstate[",
        "sqlite_error",
    ]
    try:
        baseline = session.get(url, timeout=session.request_timeout).text[:5000]
    except Exception:
        baseline = ""

    for p in payloads:
        try:
            parsed = urlparse.urlsplit(url)
            qs = dict(urlparse.parse_qsl(parsed.query, keep_blank_values=True))
            qs[param] = p
            url_mod = urlparse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlparse.urlencode(qs), parsed.fragment))
            r = session.get(url_mod, timeout=session.request_timeout)
            body = r.text[:5000].lower()
            if any(sig in body for sig in error_signatures):
                return Finding("HIGH", "SQLi", url_mod, param, f"Error-based signature with payload: {p}")
            if baseline and abs(len(r.text) - len(baseline)) > 500:
                return Finding("MEDIUM", "SQLi", url_mod, param, f"Response length changed with payload: {p}")
        except Exception:
            continue
    return None

def check_security_headers(resp: requests.Response, required: List[str]) -> List[Finding]:
    f: List[Finding] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    for h in required:
        if h.lower() not in headers:
            f.append(Finding("INFO", "Headers", resp.url, "-", f"Missing header: {h}"))
    if "strict-transport-security" not in headers and str(resp.url).startswith("https://"):
        f.append(Finding("INFO", "Headers", resp.url, "-", "No HSTS header"))
    return f

# -------------------------
# Orchestrate scan
# -------------------------
def run_scan(target: str, cfg: Dict) -> ScanResult:
    scan_start = time.time()

    out_dir = cfg.get("report", {}).get("out_dir", "reports")
    ctx = ScanContext(out_dir=out_dir, target=target)

    s_cfg = cfg.get("scanner", {})
    excl_paths = cfg.get("exclusions", {}).get("paths", [])
    excl_domains = cfg.get("exclusions", {}).get("domains", [])
    payloads = cfg.get("payloads", {})
    required_headers = cfg.get("headers_required", [])

    session = make_session(
        user_agent=s_cfg.get("user_agent", "MiniOWASP/1.0 (+https://github.com/salmanel/password-enforcer)"),
        follow_redirects=bool(s_cfg.get("follow_redirects", True)),
        timeout=int(s_cfg.get("timeout_seconds", 15)),
        verify_ssl=bool(s_cfg.get("verify_ssl", True)),
        retries=int(s_cfg.get("retries", 1)),
        backoff_factor=float(s_cfg.get("backoff_factor", 0.25)),
    )
    log.debug("HTTP session ready (timeout=%s, retries=%s)", session.request_timeout, s_cfg.get("retries", 1))

    try:
        pages, forms = crawl(
            start_url=target,
            session=session,
            max_depth=int(s_cfg.get("max_depth", 2)),
            same_host_only=bool(s_cfg.get("same_host_only", True)),
            excludes_paths=excl_paths,
            exclude_domains=excl_domains,
            follow_redirect_hosts=bool(s_cfg.get("follow_redirect_hosts", False)),
            allowed_hosts=s_cfg.get("allowed_hosts", []),
            max_pages=int(s_cfg.get("max_pages", 100)),
            delay_ms=int(s_cfg.get("delay_ms", 250)),
        )

        findings: List[Finding] = []

        # update progress after crawl discovery
        ctx.update_progress(pages=len(pages), forms=sum(len(v) for v in forms.values()))

        # Header checks for all pages
        for u in pages:
            try:
                r = session.get(u, timeout=session.request_timeout)
                hdrs = check_security_headers(r, required_headers)
                for h in hdrs:
                    findings.append(h)
                    ctx.add(h)
            except Exception as e:
                log.debug("Header check failed for %s: %s", u, e.__class__.__name__)

        # GET param tests (XSS + SQLi) for URLs with queries
        for u in pages:
            try:
                parsed = urlparse.urlsplit(u)
                qs = dict(urlparse.parse_qsl(parsed.query, keep_blank_values=True))
                if not qs:
                    continue
                # XSS
                for param in qs:
                    fx = test_reflected_xss(session, u, param, payloads.get("xss_reflected", []))
                    if fx:
                        findings.append(fx)
                        ctx.add(fx)
                # SQLi
                for param in qs:
                    fs = test_sqli_basic(session, u, param, payloads.get("sqli_basic", []))
                    if fs:
                        findings.append(fs)
                        ctx.add(fs)
            except Exception as e:
                log.debug("GET param tests failed for %s: %s", u, e.__class__.__name__)

        # Basic form fuzz:
        total_forms = 0
        for page, fs in forms.items():
            total_forms += len(fs)
            for f in fs:
                # XSS/SQLi for GET forms: current behavior kept
                if f["method"] == "get" and f["inputs"]:
                    first_param = next(iter(f["inputs"]))
                    base = urlparse.urljoin(page, f["action"])
                    parsed = urlparse.urlsplit(base)
                    base_qs = dict(urlparse.parse_qsl(parsed.query, keep_blank_values=True))

                    # XSS fuzz
                    for pld in payloads.get("xss_reflected", []):
                        q = dict(base_qs)
                        q[first_param] = pld
                        url_mod = urlparse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlparse.urlencode(q), parsed.fragment))
                        try:
                            r = session.get(url_mod, timeout=session.request_timeout)
                            if pld in r.text:
                                fnd = Finding("HIGH", "XSS", url_mod, first_param, f"Reflected payload: {pld}")
                                findings.append(fnd)
                                ctx.add(fnd)
                                break
                        except Exception:
                            pass

                    # SQLi fuzz
                    for pld in payloads.get("sqli_basic", []):
                        q = dict(base_qs)
                        q[first_param] = pld
                        url_mod = urlparse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlparse.urlencode(q), parsed.fragment))
                        try:
                            r = session.get(url_mod, timeout=session.request_timeout)
                            body = r.text.lower()
                            if any(sig in body for sig in [
                                "you have an error in your sql syntax",
                                "warning: mysql",
                                "unclosed quotation mark",
                                "sqlstate[",
                            ]):
                                fnd = Finding("HIGH", "SQLi", url_mod, first_param, f"Error signature: {pld}")
                                findings.append(fnd)
                                ctx.add(fnd)
                                break
                        except Exception:
                            pass
                else:
                    # For POST forms: gentle POST fuzz (first param only)
                    if f["method"] == "post" and f["inputs"]:
                        first_param = next(iter(f["inputs"]))
                        base = urlparse.urljoin(page, f["action"])
                        for pld in payloads.get("xss_reflected", [])[:5]:
                            try:
                                data = dict(f["inputs"])
                                data[first_param] = pld
                                r = session.post(base, data=data, timeout=session.request_timeout)
                                if pld in r.text:
                                    fnd = Finding("HIGH", "XSS", base, first_param, f"Reflected payload (POST): {pld}")
                                    findings.append(fnd)
                                    ctx.add(fnd)
                                    break
                            except Exception:
                                continue
                        for pld in payloads.get("sqli_basic", [])[:5]:
                            try:
                                data = dict(f["inputs"])
                                data[first_param] = pld
                                r = session.post(base, data=data, timeout=session.request_timeout)
                                body = r.text.lower()
                                if any(sig in body for sig in [
                                    "you have an error in your sql syntax",
                                    "warning: mysql",
                                    "unclosed quotation mark",
                                    "sqlstate[",
                                ]):
                                    fnd = Finding("HIGH", "SQLi", base, first_param, f"Error signature (POST): {pld}")
                                    findings.append(fnd)
                                    ctx.add(fnd)
                                    break
                            except Exception:
                                continue

        # Final progress update
        ctx.update_progress(pages=len(pages), forms=total_forms)

        scan_end = time.time()
        result = ScanResult(
            target=target,
            pages=pages,
            forms=forms,
            crawled_pages=len(pages),
            discovered_forms=total_forms,
            findings=findings,
            started_at=scan_start,
            finished_at=scan_end,
        )

        # produce classic final reports (JSON + HTML)
        try:
            save_report(result, out_dir)
        except Exception:
            log.exception("save_report failed")

        return result
    finally:
        # ensure reporter closed on exit
        try:
            ctx.close()
        except Exception:
            pass

# -------------------------
# Reporting (final pretty JSON + HTML)
# -------------------------
def save_report(result: ScanResult, out_dir: str) -> Tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S", time.localtime(result.finished_at))
    base = os.path.join(out_dir, f"report_{ts}")

    # JSON
    json_path = base + ".json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "target": result.target,
            "pages": result.pages,
            "forms": result.forms,
            "crawled_pages": result.crawled_pages,
            "discovered_forms": result.discovered_forms,
            "findings": [asdict(x) for x in result.findings],
            "started_at": result.started_at,
            "finished_at": result.finished_at,
        }, f, indent=2)

    # Group findings for pretty HTML
    groups = {"HIGH": [], "MEDIUM": [], "INFO": []}
    for fd in result.findings:
        sev = fd.severity.upper()
        if sev not in groups:
            sev = "INFO"
        groups[sev].append(fd)

    # badging + sort
    def sev_badge(s):
        s = s.upper()
        if s == "HIGH":
            return "<span class='chip chip-high'>HIGH</span>"
        if s == "MEDIUM":
            return "<span class='chip chip-med'>MEDIUM</span>"
        return "<span class='chip chip-info'>INFO</span>"

    # build rows
    def rows_for(findings: List[Finding]) -> str:
        parts = []
        for fnd in findings:
            parts.append(
                "<tr>"
                f"<td>{sev_badge(fnd.severity)}</td>"
                f"<td>{html.escape(fnd.category)}</td>"
                f"<td class='url'>{html.escape(fnd.url)}</td>"
                f"<td>{html.escape(fnd.param)}</td>"
                f"<td>{html.escape(fnd.evidence)}</td>"
                "</tr>"
            )
        return "\n".join(parts) or (
            "<tr><td colspan='5' class='muted'>No findings in this section.</td></tr>"
        )

    # chips / stats
    total_findings = len(result.findings)
    high_cnt = len(groups["HIGH"])
    med_cnt  = len(groups["MEDIUM"])
    info_cnt = len(groups["INFO"])

    started_epoch  = int(result.started_at)
    finished_epoch = int(result.finished_at)

    # HTML
    html_path = base + ".html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Mini OWASP Report</title>
<style>
:root {{
  --bg: #0f172a;       /* slate-900 */
  --panel: #111827;    /* gray-900 */
  --panel-2: #0b1220;  /* deep navy blend */
  --text: #e5e7eb;     /* gray-200 */
  --muted: #9ca3af;    /* gray-400 */
  --line: #1f2937;     /* gray-800 */
  --chip: #1f2937;
  --chip-text: #cbd5e1;
  --high: #ef4444;     /* red-500 */
  --med:  #f59e0b;     /* amber-500 */
  --info: #60a5fa;     /* blue-400 */
}}
* {{ box-sizing: border-box }}
body {{
  margin: 0; padding: 24px 28px; background: var(--bg); color: var(--text);
  font-family: system-ui, Segoe UI, Roboto, Arial, sans-serif; line-height: 1.4;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{
  margin: 0 0 12px 0; font-size: 28px; font-weight: 800;
}}
.small {{ color: var(--muted); font-size: 14px }}
.chips {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 14px 0 22px }}
.badge {{
  padding: 8px 12px; border-radius: 999px; background: var(--panel);
  border: 1px solid var(--line); color: var(--text); font-size: 13px;
}}
.badge .dot {{ display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:8px; vertical-align:1px }}
.badge.high .dot {{ background: var(--high) }}
.badge.med .dot  {{ background: var(--med)  }}
.badge.info .dot {{ background: var(--info) }}

.section-title {{ font-size: 20px; font-weight: 800; margin: 22px 0 10px }}
.panel {{
  background: linear-gradient(180deg, var(--panel), var(--panel-2));
  border: 1px solid var(--line); border-radius: 12px; overflow: hidden;
}}

table {{ width: 100%; border-collapse: collapse; }}
thead th {{
  text-align: left; font-weight: 700; font-size: 13px; color: var(--muted);
  padding: 12px 14px; background: rgba(255,255,255,0.03); border-bottom: 1px solid var(--line);
}}
tbody td {{
  padding: 12px 14px; border-bottom: 1px solid var(--line); vertical-align: top;
  font-size: 14px;
}}
tbody tr:hover {{ background: rgba(255,255,255,0.02); }}
td.url {{ word-break: break-all }}

.chip {{
  display:inline-block; padding: 4px 10px; border-radius: 999px; font-weight: 700; font-size: 12px;
  color: #fff;
}}
.chip-high {{ background: var(--high) }}
.chip-med  {{ background: var(--med)  }}
.chip-info {{ background: #334155; color: #cbd5e1 }} /* slate-700 */

.muted {{ color: var(--muted); text-align:center }}
.section-spacer {{ height: 16px }}
</style>
</head>
<body>
<div class="container">

  <h1>Mini OWASP Report</h1>
  <div class="small">Target: {html.escape(result.target)} &bull; Pages: {result.crawled_pages} &bull; Forms: {result.discovered_forms}</div>

  <div class="chips">
    <div class="badge"><span class="dot"></span><b>Started:</b> {started_epoch}</div>
    <div class="badge"><span class="dot"></span><b>Finished:</b> {finished_epoch}</div>
    <div class="badge"><span class="dot"></span><b>Findings:</b> {total_findings}</div>
    <div class="badge high"><span class="dot"></span><b>HIGH:</b> {high_cnt}</div>
    <div class="badge med"><span class="dot"></span><b>MEDIUM:</b> {med_cnt}</div>
    <div class="badge info"><span class="dot"></span><b>INFO/LOW:</b> {info_cnt}</div>
  </div>

  <div class="section-title">High Severity</div>
  <div class="panel">
    <table>
      <thead>
        <tr><th>Severity</th><th>Category</th><th>URL</th><th>Param</th><th>Evidence</th></tr>
      </thead>
      <tbody>
        {rows_for(groups["HIGH"])}
      </tbody>
    </table>
  </div>

  <div class="section-spacer"></div>

  <div class="section-title">Medium Severity</div>
  <div class="panel">
    <table>
      <thead>
        <tr><th>Severity</th><th>Category</th><th>URL</th><th>Param</th><th>Evidence</th></tr>
      </thead>
      <tbody>
        {rows_for(groups["MEDIUM"])}
      </tbody>
    </table>
  </div>

  <div class="section-spacer"></div>

  <div class="section-title">Information / Low</div>
  <div class="panel">
    <table>
      <thead>
        <tr><th>Severity</th><th>Category</th><th>URL</th><th>Param</th><th>Evidence</th></tr>
      </thead>
      <tbody>
        {rows_for(groups["INFO"])}
      </tbody>
    </table>
  </div>

</div>
</body>
</html>""")

    return json_path, html_path

# -------------------------
# Pretty helpers
# -------------------------
def summary_text(result: ScanResult) -> str:
    high = sum(1 for f in result.findings if f.severity == "HIGH")
    med  = sum(1 for f in result.findings if f.severity == "MEDIUM")
    info = sum(1 for f in result.findings if f.severity in ("LOW", "INFO"))
    return f"Pages: {result.crawled_pages} | Forms: {result.discovered_forms} | HIGH: {high} | MEDIUM: {med} | INFO: {info}"
