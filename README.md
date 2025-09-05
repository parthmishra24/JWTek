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
- Optional `-pubkey` to verify RS256 signatures
- Optional `-secret` to verify HS256/384/512 signatures
- `-audit` highlights suspicious privilege claims
- Tokens can also be extracted from files with `-file` or analysed in batch
  using `-analyze-all`

### 2. `exploit`
- Get exploitation tips, generate PoC tokens, or attempt auth bypass testing

### 3. `forge`
- Create or convert tokens using `none`, `HS256`, or `RS256`


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

- Static analysis of JWTs with optional RS256 or HS256/384/512 signature verification
- Detects `alg: none`, weak algorithms, missing or expired claims
- Flags `jku`/`x5u` headers and unusual `kid` patterns
- Audits claims for potential privilege escalation
- RS256 → HS256 downgrade detection
- Extracts tokens from files and supports batch analysis
- Forge custom tokens or convert existing ones using `none`, `HS256`, or `RS256`
- Guided exploitation advice with PoCs and bypass testing
- Extendable and modular structure
- Colored console output for readability (disable with `-no-color` or `JWTEK_NO_COLOR=1`)

---

## 🧰 Usage

```bash
jwtek <command> [options]
```
The `jwtek` command becomes available after installation.
Use `-no-color` or set `JWTEK_NO_COLOR=1` to disable ANSI colours.

### 🔍 Analyze a JWT

Use `-analyze-all` to extract and analyze every JWT from a file. Differences
between sequential tokens are displayed automatically at the end of the output.

```bash
jwtek analyze -token <JWT>
jwtek analyze -token <JWT> -pubkey ./public.pem -audit
jwtek analyze -token <JWT> -jwks <JWKS_URL>
jwtek analyze -token <JWT> -secret mysecret
jwtek analyze -file ./tokens.txt -analyze-all
jwtek analyze -login https://example.com/login -dashboard https://example.com/app
jwtek analyze -login https://example.com/login -dashboard https://example.com/app -sP myjwt.txt
```

Using `-login` and `-dashboard` launches a Chromium browser via Playwright. Log
in manually on the provided login page, press Enter in the terminal, and JWTEK
will navigate to the dashboard, capturing any JWTs from network traffic, cookies
and web storage. Tokens are saved to `jwt.txt` by default or to a custom path
specified with `-sP` for further analysis.

### 💣 Exploitation Guidance

```bash
jwtek exploit -vuln alg-none
jwtek exploit -vuln hs256-key-found -secret secret123
jwtek exploit -vuln alg-swap-rs256
jwtek exploit -vuln jku-header
jwtek exploit -vuln suspicious-kid
```

```bash
# List all exploit IDs
jwtek exploit -list
```

### ✨ Forge a JWT

The `forge` command can create a token from a JSON payload or convert an existing JWT using `-token`.

```bash
# Forge from a payload
jwtek forge -alg HS256 -payload '{"sub":"1234567890","name":"John Doe","admin":true}' -secret secret

# Convert an RS256 token to alg none
jwtek forge -alg none -token <JWT>
```

### 🔄 Update JWTEK

```bash
jwtek update
```

## 🧠 Author

- **Parth Mishra** – Security Engineer | AppSec
- 🔗 [LinkedIn](https://www.linkedin.com/in/parthmishra24/)

---

## ⚠️ Usage Disclaimer

JWTEK is provided **for educational and authorized security testing purposes only**.
Any unauthorized or malicious use is strictly prohibited and may violate applicable
laws. Always obtain explicit permission before testing systems that you do not own.

