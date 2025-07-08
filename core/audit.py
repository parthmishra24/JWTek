def audit_claims(payload):
    print("\n[🔍] Running claim audit...")

    suspicious_keys = {
        "admin": lambda v: v in [True, "true", 1, "1", "yes"],
        "isAdmin": lambda v: v in [True, "true", 1],
        "role": lambda v: str(v).lower() in ["admin", "root", "superuser"],
        "privilege": lambda v: str(v).lower() in ["admin", "root", "superuser"],
        "scope": lambda v: "*" in str(v) or "admin" in str(v),
        "access_level": lambda v: str(v).lower() in ["admin", "root"],
        "root": lambda v: v in [True, 1, "1", "true"]
    }

    flagged = False

    for key, check in suspicious_keys.items():
        if key in payload and check(payload[key]):
            print(f"[!] Suspicious claim: `{key}` = {payload[key]}")
            flagged = True

    if not flagged:
        print("[+] No suspicious claims found.")
    else:
        print("[!] Review the above claims for potential privilege escalation.")
