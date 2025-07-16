# 🛡️ JWTEK - JWT Security Analysis & Exploitation Tool

**JWTEK** is a powerful command-line tool that helps security engineers and red teamers analyze, identify, and exploit common vulnerabilities in JSON Web Tokens (JWT).

---

## 🔎 What Is JWTEK?

**JWTEK** is a **command-line tool** designed to **analyze**, **detect vulnerabilities**, and **simulate attacks** on JSON Web Tokens (JWTs).

JWTs are widely used for **authentication and authorization**, but they’re often **misconfigured or poorly implemented** — leading to critical vulnerabilities. JWTEK helps security engineers, red teamers, and learners find those issues quickly and understand how to exploit them safely in controlled environments.

---

## ⚙️ How JWTEK Works

JWTEK is organised into several subcommands so you can analyse tokens in
different ways:

### 1. `analyze`
- Decode a token and run static checks
- Optional `--pubkey` to verify RS256 signatures
- `--audit` highlights suspicious privilege claims
- Tokens can also be extracted from files with `--file` or analysed in batch
  using `--analyze-all`

### 2. `brute-force`
- Discover the secret for HS256 tokens using a wordlist

### 3. `exploit`
- Get exploitation tips, generate PoC tokens, or attempt auth bypass testing

### 4. `forge`
- Create custom tokens using `none`, `HS256`, or `RS256`

---

## Installation
1. Clone the repository
   ```
   git clone https://github.com/parthmishra24/JWTek.git
   ```
2. Change the directory
   ```
   cd JWTek
   ```
3. Run the pip command
   ```
   pip3 install -e .
   ```

### Install with `pipx`
You can also install JWTEK globally using [pipx](https://pypa.github.io/pipx/),
which keeps the tool isolated from your other Python packages.

```bash
pipx install git+https://github.com/parthmishra24/JWTek.git
# or, if published on PyPI
pipx install jwtek
```
---

## 🚀 Features

- Static analysis of JWTs with optional RS256 signature verification
- Detects `alg: none`, weak algorithms, missing or expired claims
- Audits claims for potential privilege escalation
- Brute-forces HS256 secrets using custom or preset wordlists
- RS256 → HS256 downgrade detection
- Extracts tokens from files and supports batch analysis
- Forge custom tokens using `none`, `HS256`, or `RS256`
- Guided exploitation advice with PoCs and bypass testing
- Extendable and modular structure
- Colored console output for readability (disable with `--no-color` or `JWTEK_NO_COLOR=1`)

---

## 🧰 Usage

```bash
python3 jwtek.py <command> [options]
```
Use `--no-color` or set `JWTEK_NO_COLOR=1` to disable ANSI colours.

### 🔍 Analyze a JWT

Use `--analyze-all` to extract and analyze every JWT from a file. Differences
between sequential tokens are displayed automatically at the end of the output.

```bash
python3 jwtek.py analyze --token <JWT>
python3 jwtek.py analyze --token <JWT> --pubkey ./public.pem --audit
python3 jwtek.py analyze --token <JWT> --jwks <JWKS_URL>
python3 jwtek.py analyze --file ./tokens.txt --analyze-all
```

### 🔐 Brute-force HS256

```bash
python3 jwtek.py brute-force --token <JWT> --wordlist testlist.txt
```

Preset names such as `rockyou`, `jwt-secrets`, and `top10` can be used in place
of a file path. JWTEK expects these wordlists at the following locations:

- `rockyou` → `/usr/share/wordlists/rockyou.txt`
- `jwt-secrets` → `data/wordlists/jwt-secrets.txt`
- `top10` → `data/wordlists/top10.txt`

If a preset wordlist isn't found at its location, JWTEK will display an error
and you can supply your own wordlist path with `--wordlist`.

The base directory for these presets can also be changed by setting the
`JWTEK_WORDLIST_DIR` environment variable. On Linux this usually points to
`/usr/share/wordlists` or a similar folder. macOS and Windows users may set the
variable to their own wordlist directory.

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

### ✨ Forge a JWT

```bash
python3 jwtek.py forge --alg HS256 --payload '{"admin": true}' --secret secret
```


## 🧠 Author

- **Parth Mishra** – Security Engineer | AppSec
- 🔗 [LinkedIn](https://www.linkedin.com/in/parthmishra24/)

---

## ⚠️ Usage Disclaimer

JWTEK is provided **for educational and authorized security testing purposes only**.
Any unauthorized or malicious use is strictly prohibited and may violate applicable
laws. Always obtain explicit permission before testing systems that you do not own.

