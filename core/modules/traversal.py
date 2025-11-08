from urllib.parse import urlencode
import requests

def run_traversal_checks(pages, session, cfg):
    findings = []
    cand_params = cfg.get("params", ["file","path","dir","page","include","template","document"])
    fuzz = cfg.get("fuzz", ["../../../../etc/passwd","..%2f..%2fetc%2fpasswd","..\\..\\..\\..\\windows\\win.ini","../"])

    sample = list(pages)[:30]
    for base in sample:
        for param in cand_params:
            for payload in fuzz:
                try:
                    sep = "&" if "?" in base else "?"
                    u = f"{base}{sep}{param}={requests.utils.quote(payload, safe='')}"
                    r = session.get(u, timeout=8, verify=False)
                    body = r.text.lower()
                    if "root:x:" in body or "[fonts]" in body or "for 16-bit app support" in body:
                        findings.append({
                            "severity":"HIGH",
                            "category":"Traversal",
                            "url":u, "param":param,
                            "evidence":"OS file signature found (passwd/win.ini)"
                        })
                        break
                except Exception:
                    pass
    return findings

