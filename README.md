# 🛡️ JWTEK - JWT Security Analysis & Exploitation Tool

**JWTEK** is a powerful command-line tool that helps security engineers and red teamers analyze, identify, and exploit common vulnerabilities in JSON Web Tokens (JWT).

---

## 🔎 What Is JWTEK?

**JWTEK** is a **command-line tool** designed to **analyze**, **detect vulnerabilities**, and **simulate attacks** on JSON Web Tokens (JWTs).

JWTs are widely used for **authentication and authorization**, but they’re often **misconfigured or poorly implemented** — leading to critical vulnerabilities. JWTEK helps security engineers, red teamers, and learners find those issues quickly and understand how to exploit them safely in controlled environments.

---

## ⚙️ How JWTEK Works

JWTEK operates in multiple **modes** to support both black-box and gray-box analysis:

### 1. Static Analysis
- Input: Just a JWT (no key needed)
- JWTEK decodes the token and checks for:
  - `alg: none` misconfigurations
  - Use of weak algorithms (like HS256)
  - Missing or expired claims (`exp`, `iat`, `nbf`)
  - RS256 → HS256 downgrade potential

### 2. Brute-Force Mode (HS256)
- Input: JWT signed with HS256 + a wordlist
- JWTEK tries each secret in the wordlist to **guess the HMAC key**
- If successful:
  - Reveals the secret
  - Enables token forgery
  - Provides exploit guidance

### 3. Signature Verification (RS256)
- Input: JWT + public key file
- JWTEK verifies if the token’s signature is valid
- Helps confirm token integrity and detect tampering

### 4. Exploit Guidance
- Run:
  ```bash
  jwtek.py exploit --vuln <id>
  ```
- JWTEK shows:
  - Why the issue is dangerous
  - How to exploit it manually
  - Python PoC examples

---

## 🚀 Features

- ✅ Static analysis of JWTs
- ✅ Detects `alg: none`, weak algorithms, missing claims, expired tokens
- ✅ Brute-force HS256 tokens using custom or preset wordlists
- ✅ RS256 to HS256 downgrade vulnerability detection
- ✅ Signature verification using RS256 public keys
- ✅ Guided exploitation advice with real PoCs
- ✅ Extendable and modular structure

---

## 🧰 Usage

```bash
python3 jwtek.py <command> [options]
```

### 🔍 Analyze a JWT

```bash
python3 jwtek.py analyze --token <JWT>
python3 jwtek.py analyze --token <JWT> --pubkey ./public.pem
```

### 🔐 Brute-force HS256

```bash
python3 jwtek.py brute-force --token <JWT> --wordlist testlist.txt
```

### 💣 Exploitation Guidance

```bash
python3 jwtek.py exploit --vuln alg-none
python3 jwtek.py exploit --vuln hs256-key-found --secret secret123
python3 jwtek.py exploit --vuln alg-swap-rs256
```

```bash
# List all exploit IDs
python3 jwtek.py exploit --list
```

---

## 🧠 Author

- **Parth Mishra** – Security Engineer | Red Teamer | Python Builder  
- 🔗 [LinkedIn](https://linkedin.com/in/parth-mishra)

---

## 📜 License

This project is licensed for educational and security testing purposes only.  
Use responsibly and only on systems you have permission to test.
```
