# core/brute_forcer.py

import os
import jwt
from jwt.exceptions import InvalidSignatureError, DecodeError
from tqdm import tqdm

# Preset wordlist mapping (if used)
PRESET_WORDLISTS = {
    "rockyou": "/usr/share/wordlists/rockyou.txt",
    "jwt-secrets": "data/wordlists/jwt-secrets.txt",
    "top10": "data/wordlists/top10.txt"
}

def resolve_wordlist_path(wordlist_input):
    if wordlist_input in PRESET_WORDLISTS:
        resolved = PRESET_WORDLISTS[wordlist_input]
        if not os.path.exists(resolved):
            print(f"[!] Preset '{wordlist_input}' not found at expected location: {resolved}")
            return None
        return resolved
    elif os.path.exists(wordlist_input):
        return wordlist_input
    else:
        print(f"[!] Provided wordlist path is invalid: {wordlist_input}")
        return None


def brute_force_hs256(token, wordlist_input):
    wordlist_path = resolve_wordlist_path(wordlist_input)
    if not wordlist_path:
        return

    try:
        header_b64, payload_b64, signature = token.split(".")
    except ValueError:
        print("[!] Invalid JWT format.")
        return

    print(f"\n[~] Starting brute-force on HS256 token using: {wordlist_path}")

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            def word_gen():
                for line in f:
                    word = line.strip()
                    if word:
                        yield word

            for word in tqdm(word_gen(), desc="Trying secrets"):
                try:
                    jwt.decode(token, word, algorithms=["HS256"])
                    print(f"\n[+] Secret key FOUND: '{word}'")
                    return word
                except (InvalidSignatureError, DecodeError):
                    continue
                except Exception as e:
                    print(f"[!] Error occurred during decode: {e}")
                    break
    except Exception as e:
        print(f"[!] Failed to read wordlist: {e}")
        return

    print("[-] Secret not found in the wordlist.")
    return None
