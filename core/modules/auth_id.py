import re

LOGIN_HINTS = ["login","signin","logon","auth"]
USER_HINTS  = ["user","username","email","mail"]
PASS_HINTS  = ["pass","password","pwd"]

def run_auth_id_checks(pages, forms, session):
    findings = []
    # 1) Weak login form heuristics (missing autocomplete=off / type=password)
    for f in forms:
        action = f.get("action") or f.get("page")
        inputs = " ".join([i.lower() for i in f.get("inputs",[])])
        if any(h in (action or "").lower() for h in LOGIN_HINTS):
            if not any("type=password" in i for i in f.get("raw_inputs", [])):
                findings.append({
                    "severity":"MEDIUM",
                    "category":"Auth",
                    "url": action, "param":"– (no parameter)",
                    "evidence":"Login-like form without a password field (type=password) detected"
                })
            # sparse heuristic: no autocomplete hints
            if "autocomplete" not in inputs:
                findings.append({
                    "severity":"LOW",
                    "category":"Auth",
                    "url": action, "param":"– (no parameter)",
                    "evidence":"Login-like form without autocomplete directives"
                })
    # 2) Sensitive pages over HTTP
    for u in pages:
        if u.lower().startswith("http://") and any(h in u.lower() for h in LOGIN_HINTS):
            findings.append({
                "severity":"HIGH",
                "category":"Crypto",
                "url":u, "param":"-",
                "evidence":"Login over plain HTTP"
            })
    return findings
