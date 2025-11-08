#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Lightweight crawler used by wvscanner_core.

Exports
-------
crawl_site(start_url: str, config: dict, session: requests.Session)
    -> Tuple[List[str], List[dict], Dict[str, Dict[str, str]]]

- pages: list of visited page URLs (strings)
- forms: list of discovered forms:
    {
        "page": <url>,
        "method": "GET"|"POST",
        "action": <absolute url or page url>,
        "inputs": ["name1","name2",...]
    }
- headers_by_url: { url -> {header_name: value, ...} }
"""

from __future__ import annotations

from typing import Tuple, List, Dict, Set
from urllib.parse import urlparse, urljoin
import time
import re
import requests
from bs4 import BeautifulSoup

# -------------------------
# helpers
# -------------------------

def _norm_url(u: str) -> str:
    if not u:
        return u
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    # strip fragments; keep query & path
    p = urlparse(u)
    path = p.path or "/"
    return p._replace(fragment="", path=path).geturl()

def _same_host(u1: str, u2: str) -> bool:
    try:
        return urlparse(u1).netloc.lower() == urlparse(u2).netloc.lower()
    except Exception:
        return False

def _is_allowed_host(url: str, allowed_hosts: List[str]) -> bool:
    if not allowed_hosts:
        return True
    host = urlparse(url).netloc.lower()
    for pat in allowed_hosts:
        pat = pat.strip().lower()
        if not pat:
            continue
        if host == pat or host.endswith("." + pat):
            return True
    return False

def _is_excluded_href(href: str, exclusions: List[str]) -> bool:
    if not href:
        return True
    h = href.strip().lower()
    for token in exclusions:
        if token and token.lower() in h:
            return True
    return False

def _extract_links(base_url: str, html: str, exclusions: List[str]) -> List[str]:
    out: List[str] = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return out
    for a in soup.find_all("a", href=True):
        href = a.get("href") or ""
        if _is_excluded_href(href, exclusions):
            continue
        # resolve relative
        absu = urljoin(base_url, href)
        absu = _norm_url(absu)
        out.append(absu)
    # de-dup while preserving order
    seen: Set[str] = set()
    dedup = []
    for u in out:
        if u not in seen:
            seen.add(u)
            dedup.append(u)
    return dedup

def _extract_forms(page_url: str, html: str) -> List[dict]:
    forms: List[dict] = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return forms

    for f in soup.find_all("form"):
        method = (f.get("method") or "GET").strip().upper()
        action = f.get("action") or page_url
        action = urljoin(page_url, action)
        inputs: List[str] = []
        # input, textarea, select names
        for tag in f.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                inputs.append(name)
        # dedup inputs
        seen = set()
        inputs = [i for i in inputs if not (i in seen or seen.add(i))]
        forms.append({
            "page": page_url,
            "method": method,
            "action": action,
            "inputs": inputs,
        })
    return forms

# -------------------------
# fetch
# -------------------------

def _fetch(session: requests.Session, url: str, timeout: int, delay_ms: int) -> requests.Response | None:
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        # polite delay between requests
        if delay_ms and delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        return resp
    except requests.RequestException:
        return None

# -------------------------
# public API
# -------------------------

def crawl_site(start_url: str, config: dict, session: requests.Session) -> Tuple[List[str], List[dict], Dict[str, Dict[str, str]]]:
    """
    Main crawler routine.
    Respects:
      config["scanner"]: {max_depth, max_pages, delay_ms, same_host_only, follow_redirect_hosts, allowed_hosts, timeout_seconds}
      config["exclusions"]["paths"]: list of substrings to avoid (e.g., .png, .pdf, mailto:, javascript:)
    """
    scn = config.get("scanner", {})
    excl = config.get("exclusions", {})
    exclusions = excl.get("paths", []) or []

    start_url = _norm_url(start_url)

    max_depth = int(scn.get("max_depth", 2))
    max_pages = int(scn.get("max_pages", 100))
    delay_ms  = int(scn.get("delay_ms", 250))
    same_host_only = bool(scn.get("same_host_only", True))
    follow_redirect_hosts = bool(scn.get("follow_redirect_hosts", False))
    allowed_hosts = scn.get("allowed_hosts", []) or []
    timeout_seconds = int(scn.get("timeout_seconds", 15))

    visited: List[str] = []
    visited_set: Set[str] = set()
    q: List[Tuple[str, int]] = [(start_url, 0)]

    forms: List[dict] = []
    headers_by_url: Dict[str, Dict[str, str]] = {}

    start_host = urlparse(start_url).netloc.lower()

    while q and len(visited) < max_pages:
        url, depth = q.pop(0)

        # scope rules
        if same_host_only and not _same_host(start_url, url):
            continue
        if not same_host_only and not follow_redirect_hosts:
            # even if we allow leaving the host via links, we may still restrict new hosts unless explicitly allowed
            if allowed_hosts and not _is_allowed_host(url, allowed_hosts) and not _same_host(start_url, url):
                continue

        if url in visited_set:
            continue

        resp = _fetch(session, url, timeout_seconds, delay_ms)
        if not resp:
            continue

        # if redirect crossed to a new host & follow_redirect_hosts is False, drop it (unless same host)
        final_url = _norm_url(resp.url or url)
        if not _same_host(start_url, final_url) and not follow_redirect_hosts:
            # keep original page as visited but don't expand links
            visited.append(final_url)
            visited_set.add(final_url)
            headers_by_url[final_url] = {k: v for k, v in resp.headers.items()}
            continue

        html = ""
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "text/html" in ctype or ctype == "" or "application/xhtml+xml" in ctype:
            try:
                resp.encoding = resp.encoding or resp.apparent_encoding
                html = resp.text
            except Exception:
                html = ""

        visited.append(final_url)
        visited_set.add(final_url)
        headers_by_url[final_url] = {k: v for k, v in resp.headers.items()}

        # extract forms
        if html:
            page_forms = _extract_forms(final_url, html)
            forms.extend(page_forms)

        # enqueue links
        if html and depth < max_depth:
            for link in _extract_links(final_url, html, exclusions):
                # scope again for queueing
                if same_host_only:
                    if not _same_host(start_url, link):
                        continue
                else:
                    if not follow_redirect_hosts and not _same_host(start_url, link):
                        # allow if explicitly in allowed_hosts
                        if not _is_allowed_host(link, allowed_hosts):
                            continue
                if link not in visited_set and all(link != u for (u, _) in q):
                    q.append((link, depth + 1))

    return visited, forms, headers_by_url
