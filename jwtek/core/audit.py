from . import ui


def audit_claims(payload, custom_rules=None):
    ui.info("\n[🔍] Running claim audit...")

    suspicious_keys = {
        "admin": (lambda v: v in [True, "true", 1, "1", "yes"], "high"),
        "isAdmin": (lambda v: v in [True, "true", 1], "high"),
        "role": (lambda v: str(v).lower() in ["admin", "root", "superuser"], "medium"),
        "privilege": (lambda v: str(v).lower() in ["admin", "root", "superuser"], "medium"),
        "scope": (lambda v: "*" in str(v) or "admin" in str(v), "medium"),
        "access_level": (lambda v: str(v).lower() in ["admin", "root"], "medium"),
        "root": (lambda v: v in [True, 1, "1", "true"], "high"),
    }

    if custom_rules:
        suspicious_keys.update(custom_rules)

    flagged = False

    for key, data in suspicious_keys.items():
        check = data[0] if isinstance(data, tuple) else data
        severity = data[1] if isinstance(data, tuple) else "info"
        if key in payload and check(payload[key]):
            ui.warn(f"Suspicious claim: `{key}` = {payload[key]} (severity: {severity})")
            flagged = True

    if not flagged:
        ui.success("No suspicious claims found.")
    else:
        ui.warn("Review the above claims for potential privilege escalation.")
