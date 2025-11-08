from urllib.parse import urljoin
from core.utils import fetch  # adjust if your util name differs

ADMIN_HINTS = ["admin","administrator","manage","debug","console","panel","_admin"]
VERB_TAMPER = ["PUT","DELETE","PATCH"]  # heuristic: try and ensure 405/401/403

def run_access_control_checks(pages, session, base_host:str):
    findings = []
    # 1) Guessable admin/debug paths relative to discovered roots
    roots = set()
    for u in pages:
        try:
            roots.add("/".join(u.split("/", 3)[:3]) + "/")
        except Exception:
            pass

    for root in roots:
        for hint in ADMIN_HINTS:
            cand = urljoin(root, hint)
            try:
                r = session.get(cand, timeout=10, allow_redirects=True, verify=False)
                if r.status_code in (200, 302, 301) and ("login" not in r.text.lower()):
                    findings.append({
                        "severity":"MEDIUM",
                        "category":"AccessControl",
                        "url":cand, "param":"-",
                        "evidence":f"Publicly reachable admin-like path (status {r.status_code})"
                    })
            except Exception:
                pass

    # 2) Verb tampering on discovered pages (very light)
    for u in list(pages)[:30]:  # cap for performance
        for m in VERB_TAMPER:
            try:
                r = session.request(m, u, timeout=8, allow_redirects=False, verify=False)
                if r.status_code not in (401,403,405):  # suspicious
                    findings.append({
                        "severity":"MEDIUM",
                        "category":"AccessControl",
                        "url":u, "param":"-",
                        "evidence":f"{m} returned {r.status_code} (should be 401/403/405)"
                    })
                    break
            except Exception:
                pass

    return findings
