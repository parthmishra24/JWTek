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

### 2. `exploit`
- Get exploitation tips, generate PoC tokens, or attempt auth bypass testing

### 3. `forge`
- Create custom tokens using `none`, `HS256`, or `RS256`

### 4. `update`
- Upgrade JWTEK to the latest version from GitHub

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
   python -m pip install -e .
   ```
---

## 🚀 Features

- Static analysis of JWTs with optional RS256 signature verification
- Detects `alg: none`, weak algorithms, missing or expired claims
- Audits claims for potential privilege escalation
- RS256 → HS256 downgrade detection
- Extracts tokens from files and supports batch analysis
- Forge custom tokens using `none`, `HS256`, or `RS256`
- Guided exploitation advice with PoCs and bypass testing
- Extendable and modular structure
- Colored console output for readability (disable with `--no-color` or `JWTEK_NO_COLOR=1`)
- Built-in command to update JWTEK from GitHub

---

## 🧰 Usage

```bash
jwtek <command> [options]
```
The `jwtek` command becomes available after installation.
Use `--no-color` or set `JWTEK_NO_COLOR=1` to disable ANSI colours.

### 🔍 Analyze a JWT

Use `--analyze-all` to extract and analyze every JWT from a file. Differences
between sequential tokens are displayed automatically at the end of the output.

```bash
jwtek analyze --token <JWT>
jwtek analyze --token <JWT> --pubkey ./public.pem --audit
jwtek analyze --token <JWT> --jwks <JWKS_URL>
jwtek analyze --file ./tokens.txt --analyze-all
```


### 💣 Exploitation Guidance

```bash
jwtek exploit --vuln alg-none
jwtek exploit --vuln hs256-key-found --secret secret123
jwtek exploit --vuln alg-swap-rs256
```

```bash
# List all exploit IDs
jwtek exploit --list
```

### ✨ Forge a JWT

```bash
jwtek forge --alg HS256 --payload '{"admin": true}' --secret secret
```

### ⬆️ Update JWTEK

```bash
jwtek update
```

The command uses `pip install --upgrade` and adds `--break-system-packages`
when running with pip 23 or newer.


## 🧠 Author

- **Parth Mishra** – Security Engineer | AppSec
- 🔗 [LinkedIn](https://www.linkedin.com/in/parthmishra24/)

---

## ⚠️ Usage Disclaimer

JWTEK is provided **for educational and authorized security testing purposes only**.
Any unauthorized or malicious use is strictly prohibited and may violate applicable
laws. Always obtain explicit permission before testing systems that you do not own.

