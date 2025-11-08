# core/utils.py
from __future__ import annotations

import re
import time
import logging
from pathlib import Path
from urllib.parse import urlparse, urlunparse, urljoin
from typing import Dict, Optional, Tuple, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import yaml  # optional
except Exception:
    yaml = None

log = logging.getLogger(__name__)

# -----------------------------
# URL helpers
# -----------------------------

def normalize_url(url: str) -> str:
    """
    Normalize a URL: ensure scheme, lowercase host, strip fragments/whitespace.
    """
    if not url:
        return url
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    parts = urlparse(url)
    netloc = parts.netloc.lower()
    parts = parts._replace(netloc=netloc, fragment="")
    return urlunparse(parts)

def get_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""

def is_same_host(a: str, b: str) -> bool:
    return get_domain(a) == get_domain(b)

def safe_join(base: str, path: str) -> str:
    try:
        return urljoin(base, path)
    except Exception:
        return path

# -----------------------------
# HTTP session with retries
# -----------------------------

def build_session(
    user_agent: str = "MiniOWASP/1.0 (+https://example)",
    verify_ssl: bool = True,
    retries: int = 2,
    backoff_factor: float = 0.3,
    timeout: int = 15,
) -> requests.Session:
    """
    Create a Session with a reasonable retry policy.
    """
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent})
    s.verify = verify_ssl

    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "HEAD", "OPTIONS"]),
        backoff_factor=backoff_factor,
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)

    setattr(s, "_default_timeout", timeout)
    return s

# -----------------------------
# Rate limiting utility
# -----------------------------

def sleep_ms(ms: int) -> None:
    if ms and ms > 0:
        time.sleep(ms / 1000.0)

# -----------------------------
# Core fetch helper
# -----------------------------

def fetch(
    url: str,
    *,
    method: str = "GET",
    session: Optional[requests.Session] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
    verify_ssl: Optional[bool] = None,
    timeout: Optional[int] = None,
    delay_ms: int = 0,
) -> Tuple[int, Dict[str, str], str, str]:
    """
    Minimal safe wrapper around requests to keep a consistent interface for modules.
    Returns: (status_code, response_headers_dict, body_text, final_url)
    """
    sleep_ms(delay_ms)

    url = normalize_url(url)
    close_session = False
    if session is None:
        session = build_session()
        close_session = True

    if verify_ssl is not None:
        session.verify = verify_ssl
    if timeout is None:
        timeout = getattr(session, "_default_timeout", 15)

    try:
        m = (method or "GET").upper()
        if m == "GET":
            resp = session.get(url, params=params, headers=headers or {}, allow_redirects=allow_redirects, timeout=timeout)
        elif m == "POST":
            resp = session.post(url, params=params, data=data, headers=headers or {}, allow_redirects=allow_redirects, timeout=timeout)
        elif m == "HEAD":
            resp = session.head(url, params=params, headers=headers or {}, allow_redirects=allow_redirects, timeout=timeout)
        else:
            resp = session.request(m, url, params=params, data=data, headers=headers or {}, allow_redirects=allow_redirects, timeout=timeout)

        status = resp.status_code
        hdrs = {k: (v if isinstance(v, str) else ", ".join(map(str, v))) for k, v in resp.headers.items()}
        try:
            text = resp.text
        except Exception as e:
            text = f"(failed to decode body: {e})"
        final_url = str(resp.url)
        return status, hdrs, text, final_url

    except requests.RequestException as e:
        log.debug("fetch error for %s: %s", url, e)
        return 0, {}, f"(request error: {e})", url
    finally:
        if close_session:
            try:
                session.close()
            except Exception:
                pass

def http_get(url: str, **kw) -> Tuple[int, Dict[str, str], str, str]:
    kw.setdefault("method", "GET")
    return fetch(url, **kw)

def http_post(url: str, **kw) -> Tuple[int, Dict[str, str], str, str]:
    kw.setdefault("method", "POST")
    return fetch(url, **kw)

# -----------------------------
# Config helpers
# -----------------------------

DEFAULT_CONFIG: Dict[str, Any] = {
    "scanner": {
        "user_agent": "MiniOWASP/1.0 (+https://example)",
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
        "paths": [
            ".jpg", ".jpeg", ".png", ".gif", ".css", ".woff", ".woff2",
            ".ttf", ".svg", ".ico", ".pdf", ".zip", "mailto:", "javascript:"
        ],
    },
    "payloads": {
        "xss_reflected": [
            "<svg onload=alert(1)>",
            "\"><img src=x onerror=alert(1)>",
        ],
        "sqli_basic": [
            "' OR '1'='1",
            "' UNION SELECT 1--",
            "\" OR 1=1--",
        ],
    },
    "headers_required": [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Strict-Transport-Security",
    ],
    "javascript": {
        "enabled": False,
        "headless": True,
        "nav_timeout_ms": 12000,
        "run_timeout_ms": 4000,
        "max_body_chars": 200000,
    },
    "report": {"json": True, "html": True, "save_hashes": False, "csv": True},
    "safety": {"allow_global_scan_flag": False},
}

def ensure_defaults(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fill any missing top-level keys from DEFAULT_CONFIG without overwriting existing values.
    """
    out = dict(DEFAULT_CONFIG)
    # shallow merge for top-level; nested dicts kept if provided
    for k, v in cfg.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            nv = dict(out[k])
            nv.update(v)
            out[k] = nv
        else:
            out[k] = v
    return out

def load_config(path: Optional[str | Path]) -> Dict[str, Any]:
    """
    Load YAML (preferred) or JSON config. If path is None or missing, returns DEFAULT_CONFIG.
    """
    if not path:
        return dict(DEFAULT_CONFIG)
    p = Path(path)
    if not p.exists():
        log.warning("Config path %s not found. Using defaults.", p)
        return dict(DEFAULT_CONFIG)

    text = p.read_text(encoding="utf-8")
    cfg: Dict[str, Any] = {}
    # Try YAML then JSON
    if yaml is not None:
        try:
            parsed = yaml.safe_load(text)
            if isinstance(parsed, dict):
                cfg = parsed
        except Exception as e:
            log.debug("YAML parse failed for %s: %s", p, e)

    if not cfg:
        try:
            import json as _json
            parsed = _json.loads(text)
            if isinstance(parsed, dict):
                cfg = parsed
        except Exception as e:
            log.error("Config parse failed for %s: %s", p, e)
            return dict(DEFAULT_CONFIG)

    return ensure_defaults(cfg)
