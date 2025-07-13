import jwt
from . import ui

def verify_signature_rs256(token, public_key_path):
    ui.info(f"\n[~] Attempting to verify RS256 signature using: {public_key_path}")
    try:
        with open(public_key_path, 'r') as f:
            pubkey = f.read()

        decoded = jwt.decode(token, pubkey, algorithms=["RS256"])
        ui.success("[+] Signature verified successfully! Token is valid.")
        ui.info(f"    Payload: {decoded}")

    except jwt.ExpiredSignatureError:
        ui.warn("Signature is valid but token is expired.")
    except jwt.InvalidSignatureError:
        ui.error("Signature is invalid! Token may have been tampered with.")
    except Exception as e:
        ui.error(f"Error verifying signature: {e}")


def verify_signature_jwks(token, jwks_url):
    ui.info(f"\n[~] Attempting to verify signature using JWKS: {jwks_url}")
    try:
        try:
            from jwt import PyJWKClient
        except Exception:
            ui.error("PyJWKClient unavailable. JWKS verification not supported.")
            return

        jwk_client = PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=[
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
                "PS256",
                "PS384",
                "PS512",
            ],
            options={"verify_aud": False},
        )
        ui.success("[+] Signature verified successfully via JWKS!")
        ui.info(f"    Payload: {decoded}")
    except jwt.ExpiredSignatureError:
        ui.warn("Signature is valid but token is expired.")
    except jwt.InvalidSignatureError:
        ui.error("Signature is invalid! Token may have been tampered with.")
    except Exception as e:
        ui.error(f"Error verifying signature using JWKS: {e}")
