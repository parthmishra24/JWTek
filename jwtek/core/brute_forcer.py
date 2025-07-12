# core/brute_forcer.py

import os
import jwt
from jwt.exceptions import InvalidSignatureError, DecodeError
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from . import ui

# Preset wordlist mapping (if used)
BASE_DIR = os.environ.get("JWTEK_WORDLIST_DIR")
PRESET_WORDLISTS = {
    "rockyou": os.path.join(BASE_DIR, "rockyou.txt") if BASE_DIR else "/usr/share/wordlists/rockyou.txt",
    "jwt-secrets": os.path.join(BASE_DIR or "data/wordlists", "jwt-secrets.txt"),
    "top10": os.path.join(BASE_DIR or "data/wordlists", "top10.txt"),
}

def resolve_wordlist_path(wordlist_input):
    if wordlist_input in PRESET_WORDLISTS:
        resolved = PRESET_WORDLISTS[wordlist_input]
        if not os.path.exists(resolved):
            ui.error(f"Preset '{wordlist_input}' not found at expected location: {resolved}")
            return None
        return resolved
    elif os.path.exists(wordlist_input):
        return wordlist_input
    else:
        ui.error(f"Provided wordlist path is invalid: {wordlist_input}")
        return None


def brute_force_hs256(token, wordlist_input, threads=1):
    wordlist_path = resolve_wordlist_path(wordlist_input)
    if not wordlist_path:
        return

    try:
        header_b64, payload_b64, signature = token.split(".")
    except ValueError:
        ui.error("Invalid JWT format.")
        return

    ui.info(f"\n[~] Starting brute-force on HS256 token using: {wordlist_path}")

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = [w.strip() for w in f if w.strip()]

        def attempt(word):
            try:
                jwt.decode(token, word, algorithms=["HS256"])
                return word
            except (InvalidSignatureError, DecodeError):
                return None

        if threads > 1:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                for word, result in zip(words, ex.map(attempt, words)):
                    if result:
                        ui.success(f"\n[+] Secret key FOUND: '{result}'")
                        return result
        else:
            for word in tqdm(words, desc="Trying secrets"):
                res = attempt(word)
                if res:
                    ui.success(f"\n[+] Secret key FOUND: '{res}'")
                    return res
    except Exception as e:
        ui.error(f"Failed to read wordlist: {e}")
        return

    ui.warn("Secret not found in the wordlist.")
    return None
