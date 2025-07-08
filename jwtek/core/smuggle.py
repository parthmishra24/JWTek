import base64
import json
from termcolor import cprint

def decode_part(b64_string):
    """Base64 decode with padding handling."""
    b64_string += '=' * (-len(b64_string) % 4)
    try:
        return base64.urlsafe_b64decode(b64_string).decode('utf-8')
    except Exception as e:
        return f"[!] Decode error: {e}"

def smuggle_compare(token1, token2, save_to=None):
    output_lines = []

    def log(msg, level="info"):
        if save_to is not None:
            output_lines.append(msg)
        if level == "info":
            cprint(msg, "white")
        elif level == "warn":
            cprint(msg, "yellow")
        elif level == "alert":
            cprint(msg, "red")
        else:
            print(msg)

    log("\n🔍 Comparing JWTs for smuggling indicators...\n")

    try:
        header1, payload1, sig1 = token1.split(".")
        header2, payload2, sig2 = token2.split(".")
    except ValueError:
        log("[!] Invalid JWT format. Ensure both tokens have three parts.", "alert")
        return

    def decode_json(part, label):
        try:
            return json.loads(decode_part(part))
        except Exception as e:
            log(f"[!] Failed to decode {label}: {e}", "alert")
            return {}

    h1 = decode_json(header1, "JWT1 Header")
    h2 = decode_json(header2, "JWT2 Header")
    p1 = decode_json(payload1, "JWT1 Payload")
    p2 = decode_json(payload2, "JWT2 Payload")

    log("─── Header Comparison ───", "info")
    for key in set(h1) | set(h2):
        if h1.get(key) != h2.get(key):
            log(f"{key}: '{h1.get(key)}' → '{h2.get(key)}'", "warn")

    log("\n─── Payload Comparison ───", "info")
    for key in set(p1) | set(p2):
        if p1.get(key) != p2.get(key):
            log(f"{key}: '{p1.get(key)}' → '{p2.get(key)}'", "warn")

    log("\n─── Signature Comparison ───", "info")
    if sig1 != sig2:
        log("Signature changed.", "alert")
    else:
        log("✔ Signature unchanged.")

    log("\n✓ Comparison complete. Review above differences for signs of smuggling.\n")

    if save_to:
        try:
            with open(save_to, "w") as f:
                f.write("\n".join(output_lines))
            cprint(f"[+] Report saved to: {save_to}", "green")
        except Exception as e:
            cprint(f"[!] Failed to save report: {e}", "red")
