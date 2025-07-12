import time

def run_all_checks(header, payload):
    print("\n[+] Running static analysis...\n")

    check_alg_none(header)
    check_weak_alg(header)
    check_missing_claims(payload)
    check_expired(payload)
    check_long_lifetime(payload)
    check_suspicious_iat(payload)
    check_rs256_alg_downgrade(header)
    check_suspicious_kid(header)

def check_alg_none(header):
    alg = header.get("alg", "")
    if alg.lower() == "none":
        print("[!] Vulnerable: alg=none detected (token may be accepted without a signature!)")
    else:
        print("[+] alg field OK:", alg)

def check_weak_alg(header):
    weak = {"HS256", "HS384", "HS512"}
    if header.get("alg") in weak:
        print(f"[!] Warning: Weak symmetric algorithm used ({header['alg']}). Brute-force may be possible.")
    else:
        print(f"[+] Algorithm used is: {header.get('alg')}")

def check_missing_claims(payload):
    required = ['exp', 'iat', 'nbf', 'aud', 'iss']
    for claim in required:
        if claim not in payload:
            print(f"[!] Missing claim: {claim}")
    print("[+] Claim check complete.")

def check_expired(payload):
    exp = payload.get('exp')
    if exp:
        now = int(time.time())
        if now > int(exp):
            print("[!] Token is expired.")
        else:
            print("[+] Token expiration OK.")

def check_long_lifetime(payload):
    exp = payload.get('exp')
    iat = payload.get('iat')
    if exp and iat:
        try:
            lifetime = int(exp) - int(iat)
            if lifetime > 3600 * 24 * 7:
                print(f"[!] Token lifetime unusually long: {lifetime} seconds")
            else:
                print("[+] Token lifetime within normal bounds.")
        except Exception:
            pass

def check_suspicious_iat(payload):
    iat = payload.get('iat')
    if iat:
        now = int(time.time())
        try:
            iat = int(iat)
            if iat > now + 300 or iat < now - (3600 * 24 * 365 * 10):
                print("[!] Suspicious issued-at (iat) timestamp:", iat)
            else:
                print("[+] iat timestamp looks reasonable.")
        except Exception:
            print("[!] Invalid iat timestamp format.")

def check_suspicious_kid(header):
    kid = header.get('kid')
    if kid:
        if '..' in kid or '/' in kid:
            print(f"[!] Suspicious kid value: {kid}")

def check_rs256_alg_downgrade(header):
    alg = header.get("alg", "")
    if alg.upper() == "RS256":
        print("[!] Warning: Token uses RS256 (asymmetric). Check if the backend verifies key type correctly.")
        print("    Possible downgrade to HS256 and signature using public key as HMAC secret.")
        print("    → Try exploit: jwtek exploit --vuln alg-swap-rs256\n")
