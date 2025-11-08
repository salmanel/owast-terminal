import re

def run_misconfig_checks(pages, session):
    findings = []
    # Directory listing: crude pattern for common indexes
    for u in list(pages)[:50]:
        try:
            r = session.get(u, timeout=8, verify=False)
            if r.status_code == 200:
                body = r.text.lower()
                if ("<title>index of /" in body) or ("<h1>index of /" in body):
                    findings.append({
                        "severity":"MEDIUM",
                        "category":"Misconfiguration",
                        "url":u, "param":"-",
                        "evidence":"Directory listing enabled"
                    })
        except Exception:
            pass
    return findings
