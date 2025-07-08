from datetime import datetime
import time

def run_all_checks(header, payload):
    print("\n[+] Running static analysis...\n")

    check_alg_none(header)
    check_weak_alg(header)
    check_missing_claims(payload)
    check_expired(payload)
    check_rs256_alg_downgrade(header)

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
    for claim in ['exp', 'iat', 'nbf']:
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

def check_rs256_alg_downgrade(header):
    alg = header.get("alg", "")
    if alg.upper() == "RS256":
        print("[!] Warning: Token uses RS256 (asymmetric). Check if the backend verifies key type correctly.")
        print("    Possible downgrade to HS256 and signature using public key as HMAC secret.")
        print("    → Try exploit: jwtek exploit --vuln alg-swap-rs256\n")
