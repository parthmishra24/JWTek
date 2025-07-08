import jwt

def verify_signature_rs256(token, public_key_path):
    print(f"\n[~] Attempting to verify RS256 signature using: {public_key_path}")
    try:
        with open(public_key_path, 'r') as f:
            pubkey = f.read()

        decoded = jwt.decode(token, pubkey, algorithms=["RS256"])
        print("[+] Signature verified successfully! Token is valid.")
        print("    Payload:", decoded)

    except jwt.ExpiredSignatureError:
        print("[!] Signature is valid but token is expired.")
    except jwt.InvalidSignatureError:
        print("[!] Signature is invalid! Token may have been tampered with.")
    except Exception as e:
        print(f"[!] Error verifying signature: {e}")
