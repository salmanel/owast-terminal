#!/usr/bin/env python3
"""
OWASP modules runner – thin dispatcher you can call from wvscanner_core.py

Usage (inside wvscanner_core.run_scan or equivalent):
    from core.owasp_modules_runner import run_all_owasp_modules
    findings += run_all_owasp_modules(pages, forms, session, config, target_host)
"""

from typing import List, Dict, Any
from core.modules.access_control import run_access_control_checks
from core.modules.csrf import run_csrf_checks
from core.modules.traversal import run_traversal_checks
from core.modules.open_redirect import run_open_redirect_checks
from core.modules.ssrf import run_ssrf_checks
from core.modules.misconfig import run_misconfig_checks
from core.modules.auth_id import run_auth_id_checks
from core.modules.integrity import run_integrity_checks
from core.modules.outdated_components import run_outdated_components_checks

def run_all_owasp_modules(
    pages: List[str],
    forms: List[Dict[str, Any]],
    session,
    config: Dict[str, Any],
    target_host: str = "",
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    mods = (config.get("modules") or {})

    if mods.get("access_control", True):
        findings += run_access_control_checks(pages, session, base_host=target_host)

    if mods.get("csrf", True):
        tn = config.get("payloads", {}).get("csrf", {}).get("token_names", [])
        findings += run_csrf_checks(pages, forms, session, token_names=tn)

    if mods.get("open_redirect", True):
        findings += run_open_redirect_checks(pages, session, config.get("payloads", {}).get("open_redirect", {}))

    if mods.get("traversal", True):
        findings += run_traversal_checks(pages, session, config.get("payloads", {}).get("traversal", {}))

    if mods.get("ssrf", True):
        findings += run_ssrf_checks(pages, session, config.get("payloads", {}).get("ssrf", {}))

    if mods.get("misconfig", True):
        findings += run_misconfig_checks(pages, session)

    if mods.get("auth_id", True):
        findings += run_auth_id_checks(pages, forms, session)

    if mods.get("integrity", True):
        findings += run_integrity_checks(pages, session)

    if mods.get("outdated_components", True):
        findings += run_outdated_components_checks(pages, session)

    return findings
