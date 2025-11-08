from __future__ import annotations
import urllib.parse as urlparse
from typing import Optional, List
from dataclasses import dataclass

@dataclass
class Finding:
    severity: str
    category: str
    url: str
    param: str
    evidence: str

def test_reflected_xss(session, url: str, param: str, payloads: List[str]) -> Optional[Finding]:
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

def test_sqli_basic(session, url: str, param: str, payloads: List[str]) -> Optional[Finding]:
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

def check_security_headers(resp, required: list[str]) -> list[Finding]:
    f: list[Finding] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    for h in required:
        if h.lower() not in headers:
            f.append(Finding("INFO", "Headers", resp.url, "-", f"Missing header: {h}"))
    if "strict-transport-security" not in headers and str(resp.url).startswith("https://"):
        f.append(Finding("INFO", "Headers", resp.url, "-", "No HSTS header"))
    return f
