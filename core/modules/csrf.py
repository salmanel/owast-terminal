import re
TOKEN_HINTS = ["csrf","xsrf","_csrf","__requestverificationtoken","_token"]

def run_csrf_checks(pages, forms, session, token_names=None):
    findings = []
    names = set((token_names or []) + TOKEN_HINTS)

    # 1) Forms using unsafe methods without a CSRF-looking input
    for f in forms:
        method = (f.get("method") or "GET").upper()
        if method in ("POST","PUT","DELETE","PATCH"):
            inputs = [i.lower() for i in f.get("inputs",[])]
            if not any(n.lower() in "".join(inputs) for n in names):
                findings.append({
                    "severity":"MEDIUM",
                    "category":"CSRF",
                    "url": f.get("action") or f.get("page"),
                    "param":"– (no parameter)",
                    "evidence":"Unsafe method form without recognizable CSRF token"
                })

    # 2) Pages with state-changing endpoints linked via GET (heuristic)
    state_words = ["delete","remove","update","change","reset","approve","transfer"]
    for u in pages:
        if any(w in u.lower() for w in state_words):
            findings.append({
                "severity":"LOW",
                "category":"CSRF",
                "url":u, "param":"-",
                "evidence":"Potential state-changing action exposed via GET (heuristic)"
            })

    return findings
