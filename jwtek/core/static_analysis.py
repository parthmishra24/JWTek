import time
from datetime import datetime
from . import ui

def run_all_checks(header, payload):
    ui.info("\n[+] Running static analysis...\n")

    check_alg_none(header)
    check_weak_alg(header)
    check_missing_claims(payload)
    check_expired(payload)
    check_long_lifetime(payload)
    check_suspicious_iat(payload)
    check_rs256_alg_downgrade(header)
    check_jku_x5u(header)
    check_suspicious_kid(header)

def check_alg_none(header):
    alg = header.get("alg", "")
    if alg.lower() == "none":
        ui.error("Vulnerable: alg=none detected (token may be accepted without a signature!)")
    else:
        ui.success(f"alg field OK: {alg}")

def check_weak_alg(header):
    weak = {"HS256", "HS384", "HS512"}
    if header.get("alg") in weak:
        ui.warn(f"Warning: Weak symmetric algorithm used ({header['alg']}). Brute-force may be possible.")
    else:
        ui.success(f"Algorithm used is: {header.get('alg')}")

def check_missing_claims(payload):
    required = ['exp', 'iat', 'nbf', 'aud', 'iss']
    for claim in required:
        if claim not in payload:
            ui.warn(f"Missing claim: {claim}")
    ui.success("Claim check complete.")

def check_expired(payload):
    exp = payload.get('exp')
    if exp:
        now = int(time.time())
        try:
            exp_int = int(exp)
            exp_human = datetime.fromtimestamp(exp_int).strftime("%Y-%m-%d %H:%M:%S")
            if now > exp_int:
                ui.warn(f"Token is expired (exp: {exp_human}).")
            else:
                ui.success(f"Token expiration OK (exp: {exp_human}).")
        except Exception:
            ui.warn("Invalid exp timestamp format.")

def check_long_lifetime(payload):
    exp = payload.get('exp')
    iat = payload.get('iat')
    if exp and iat:
        try:
            exp_int = int(exp)
            iat_int = int(iat)
            lifetime = exp_int - iat_int
            exp_human = datetime.fromtimestamp(exp_int).strftime("%Y-%m-%d %H:%M:%S")
            iat_human = datetime.fromtimestamp(iat_int).strftime("%Y-%m-%d %H:%M:%S")
            if lifetime > 3600 * 24 * 7:
                ui.warn(f"Token lifetime unusually long: {lifetime} seconds ({iat_human} -> {exp_human})")
            else:
                ui.success(f"Token lifetime within normal bounds ({iat_human} -> {exp_human}).")
        except Exception:
            pass

def check_suspicious_iat(payload):
    iat = payload.get('iat')
    if iat:
        now = int(time.time())
        try:
            iat_int = int(iat)
            iat_human = datetime.fromtimestamp(iat_int).strftime("%Y-%m-%d %H:%M:%S")
            if iat_int > now + 300 or iat_int < now - (3600 * 24 * 365 * 10):
                ui.warn(f"Suspicious issued-at (iat) timestamp: {iat_human}")
            else:
                ui.success(f"iat timestamp looks reasonable ({iat_human}).")
        except Exception:
            ui.warn("Invalid iat timestamp format.")

def check_suspicious_kid(header):
    kid = header.get('kid')
    if kid:
        patterns = ['..', '/', 'http://', 'https://']
        if any(p in kid for p in patterns):
            ui.warn(f"Suspicious kid value: {kid}")

def check_jku_x5u(header):
    jku = header.get('jku')
    x5u = header.get('x5u')
    if jku:
        ui.warn(f"jku header present: {jku}")
    if x5u:
        ui.warn(f"x5u header present: {x5u}")

def check_rs256_alg_downgrade(header):
    alg = header.get("alg", "")
    if alg.upper() == "RS256":
        ui.warn("Warning: Token uses RS256 (asymmetric). Check if the backend verifies key type correctly.")
        ui.warn("    Possible downgrade to HS256 and signature using public key as HMAC secret.")
        ui.warn("    → Try exploit: jwtek exploit -vuln alg-swap-rs256\n")
