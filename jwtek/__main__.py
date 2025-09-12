import argparse
import subprocess
from pathlib import Path
from jwtek.core import (
    parser,
    static_analysis,
    exploits,
    validator,
    forge,
    audit,
    extractor,
    bruteforce,
    ui,
    scraper,
)

def analyze_all_from_file(file_path, pubkey=None, jwks_url=None, secret=None, audit_flag=False, output_json=None):
    tokens = extractor.extract_all_jwts_from_file(file_path)
    if not tokens:
        print("[!] No JWTs found in file.")
        return

    print(f"[+] Found {len(tokens)} JWT(s) in file: {file_path}\n")

    results = []

    for i, token in enumerate(tokens, 1):
        print(f"\n=== Token #{i} ===")
        header, payload, signature = parser.decode_jwt(token)

        if not header or not payload:
            print("[!] Skipping: Invalid JWT format.")
            continue

        parser.pretty_print_jwt(header, payload, signature)
        static_analysis.run_all_checks(header, payload)

        if pubkey:
            validator.verify_signature_rs256(token, pubkey)

        if jwks_url:
            validator.verify_signature_jwks(token, jwks_url)

        if secret:
            validator.verify_signature_hmac(token, secret)

        if audit_flag:
            audit.audit_claims(payload)

        results.append({"header": header, "payload": payload})

    if len(tokens) > 1:
        print("\n[+] Showing diffs between sequential tokens...\n")
        for i in range(len(tokens) - 1):
            print(f"\n=== Diff: token #{i+1} vs token #{i+2} ===")
            h1, p1, s1 = parser.decode_jwt(tokens[i])
            h2, p2, s2 = parser.decode_jwt(tokens[i+1])

            print("--- Header ---")
            for key in sorted(set(h1) | set(h2)):
                if h1.get(key) != h2.get(key):
                    print(f"{key}: '{h1.get(key)}' -> '{h2.get(key)}'")

            print("--- Payload ---")
            for key in sorted(set(p1) | set(p2)):
                if p1.get(key) != p2.get(key):
                    print(f"{key}: '{p1.get(key)}' -> '{p2.get(key)}'")

            print("--- Signature ---")
            if s1 != s2:
                print("Signature changed")
            else:
                print("Signature unchanged")

    if output_json:
        import json
        with open(output_json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results written to {output_json}")


def update_jwtek():
    """Update JWTEK by pulling the latest changes from Git and showing changes."""
    install_cmd = (
        "git clone <repo-url> && cd jwtek && "
        "python3 -m pip install -e . --break-system-packages"
    )

    repo_root = Path(__file__).resolve().parent.parent

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=True,
            cwd=repo_root,
        )
        if result.stdout.strip() != "true":
            raise subprocess.CalledProcessError(1, "rev-parse")
    except FileNotFoundError:
        print("[!] Cannot update. JWTEK was not installed via Git. Please reinstall manually using:")
        print(f"    {install_cmd}")
        return
    except subprocess.CalledProcessError:
        print("[!] Cannot update. JWTEK was not installed via Git. Please reinstall manually using:")
        print(f"    {install_cmd}")
        return

    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
            cwd=repo_root,
        )
    except subprocess.CalledProcessError:
        print("[!] Failed to check repository status. Please run 'git status --porcelain' manually.")
        return

    if status.stdout.strip():
        print("[!] You have local changes. Please commit/stash them before updating.")
        return

    try:
        old_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=repo_root,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        old_commit = None

    try:
        subprocess.run([
            "git",
            "pull",
            "origin",
            "main",
        ], check=True, cwd=repo_root, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print("[!] Failed to update automatically. Please run:")
        print("    git pull origin main")
        err = e.stderr or e.output
        if err:
            err = err.decode() if isinstance(err, bytes) else err
            err = err.strip()
            if err:
                print(f"    Error: {err}")
        return

    try:
        new_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=repo_root,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        new_commit = None

    if not old_commit or not new_commit:
        print("[+] JWTEK has been updated.")
        return

    if old_commit == new_commit:
        print("[=] JWTEK is already up to date.")
        return

    print("[+] JWTEK has been updated.\n")

    try:
        log_output = subprocess.run(
            ["git", "log", "--pretty=format:%s", f"{old_commit}..{new_commit}"],
            capture_output=True,
            text=True,
            check=True,
            cwd=repo_root,
        ).stdout.strip()
        if log_output:
            print("Recent changes:")
            for line in log_output.splitlines():
                if line.strip():
                    print(f"- {line.strip()}")
    except subprocess.CalledProcessError:
        print("[!] Failed to list recent changes. Run 'git log' manually to see commit history.")

def main(argv=None):
    parser_cli = argparse.ArgumentParser(
        prog='jwtek',
        description="🛡️ JWTEK: JWT Security Analysis & Exploitation Tool"
    )
    parser_cli.add_argument('-n', '--no-color', action='store_true', help='Disable colored output')

    subparsers = parser_cli.add_subparsers(dest='command', help='Available commands')

    # === analyze ===
    analyze_parser = subparsers.add_parser('analyze', help='Static (or optional RS256) analysis of a JWT')
    analyze_parser.add_argument('-t', '--token', required=False, help='JWT string to analyze')
    analyze_parser.add_argument('-k', '--pubkey', help='Optional path to public key (PEM) for signature verification')
    analyze_parser.add_argument('-j', '--jwks', help='URL to JWKS for signature verification')
    analyze_parser.add_argument('-s', '--secret', help='Shared secret for HS256/384/512 verification')
    analyze_parser.add_argument('-a', '--audit', action='store_true', help='Audit JWT claims for privilege abuse')
    analyze_parser.add_argument('-f', '--file', help='Path to file to extract JWT from')
    analyze_parser.add_argument('-A', '--analyze-all', action='store_true', help='Extract and analyze all JWTs from file')
    analyze_parser.add_argument('-o', '--json-out', help='Write analysis results to JSON file')
    analyze_parser.add_argument('-l', '--login', help='Login URL for interactive scraping')
    analyze_parser.add_argument('-d', '--dashboard', help='Dashboard URL for scraping after login')
    analyze_parser.add_argument('-S', '--save-path', help='Path to save scraped JWTs')

    # === exploit ===
    exploit_parser = subparsers.add_parser('exploit', help='Show exploitation guidance')
    exploit_parser.add_argument('-v', '--vuln', help='Vulnerability ID (e.g., alg-none)')
    exploit_parser.add_argument('-s', '--secret', help='Optional secret key (for PoC or bypass)')
    exploit_parser.add_argument('-u', '--url', help='Target URL for bypass testing')
    exploit_parser.add_argument('-j', '--jwks', help='JWKS URL to fetch key for certain exploits')
    exploit_parser.add_argument('-p', '--poc', action='store_true', help='Generate PoC token')
    exploit_parser.add_argument('-b', '--bypass', action='store_true', help='Attempt authentication bypass using token')
    exploit_parser.add_argument('-l', '--list', action='store_true', help='List available vulnerability IDs')

    # === forge ===
    forge_parser = subparsers.add_parser('forge', help="Forge a custom JWT token")
    forge_parser.add_argument('-a', '--alg', required=True, help="Algorithm to use (HS256, RS256, ES256, PS256, none)")
    forge_parser.add_argument('-p', '--payload', required=False, help="JSON payload string, e.g. '{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}' (optional if -t/--token is provided)")
    forge_parser.add_argument('-t', '--token', help='Existing JWT to convert/re-sign')
    forge_parser.add_argument('-s', '--secret', help="Secret key for HS256 (optional)")
    forge_parser.add_argument('-k', '--pubkey', help='Path to RSA public key (for RS256)')
    forge_parser.add_argument('-r', '--privkey', help='Path to RSA private key (for RS256/ES256/PS256)')
    forge_parser.add_argument('-i', '--kid', help='Optional kid header value')

    # === brute ===
    brute_parser = subparsers.add_parser('brute', help='Brute force HS* secret key')
    brute_parser.add_argument('-t', '--token', required=True, help='JWT token to crack')
    brute_parser.add_argument('-w', '--wordlist', required=True, help='Path to wordlist of secrets')

    # === update ===
    subparsers.add_parser('update', help='Update JWTEK to the latest version')


    args = parser_cli.parse_args()
    if getattr(args, 'no_color', False):
        ui.set_no_color(True)
    token = None

    if args.command == 'analyze':
        token = getattr(args, 'token', None)

        if args.login and args.dashboard:
            out_path = args.save_path or "jwt.txt"
            scraper.login_and_scrape(args.login, args.dashboard, out_path=out_path)
            if not token and not getattr(args, 'file', None):
                token = extractor.extract_from_file(out_path)
                if token:
                    print(f"[+] Extracted JWT:\n{token}\n")
                else:
                    print("[!] No JWTs found in scraped data.")
                    return

        if getattr(args, 'analyze_all', False) and getattr(args, 'file', None):
            analyze_all_from_file(
                args.file,
                pubkey=args.pubkey,
                jwks_url=args.jwks,
                secret=args.secret,
                audit_flag=args.audit,
                output_json=args.json_out,
            )
            return

        # 🔍 If no token is provided, try extracting from file
        if not token and getattr(args, 'file', None):
            token = extractor.extract_from_file(args.file)
            if not token:
                print("[!] No valid JWT found in file.")
                return
            else:
                print(f"[+] Extracted JWT:\n{token}\n")

        if not token:
            print("[!] Please provide a JWT token using -t/--token or extract it using -f/--file.")
            return

        # 🧠 Proceed to analyze the token
        header, payload, signature = parser.decode_jwt(token)

        if not header or not payload:
            print("[!] Could not decode JWT. Check if the format is valid.")
            return

        ui.section("Decoded JWT")
        parser.pretty_print_jwt(header, payload, signature)

        ui.section("Static Analysis")
        static_analysis.run_all_checks(header, payload)

        if args.pubkey:
            validator.verify_signature_rs256(token, args.pubkey)

        if args.jwks:
            validator.verify_signature_jwks(token, args.jwks)

        if args.secret:
            validator.verify_signature_hmac(token, args.secret)

        if args.audit:
            audit.audit_claims(payload)

        if args.json_out:
            import json
            with open(args.json_out, "w") as f:
                json.dump({"header": header, "payload": payload}, f, indent=2)


    elif args.command == 'exploit':
        ui.section("💣 Exploit Guidance")
        if args.list:
            exploits.list_available_exploits()
        elif args.vuln:
            if args.poc:
                exploits.generate_poc_token(args.vuln, secret=args.secret, jwks_url=args.jwks)
            elif args.bypass:
                if not args.url:
                    print("[!] -u/--url is required for bypass testing.")
                else:
                    exploits.attempt_bypass(args.vuln, args.secret or "", args.url, jwks_url=args.jwks)
            else:
                exploits.explain_exploit(args.vuln, secret=args.secret)
        else:
            print("[!] Use -v/--vuln to specify a vulnerability ID or -l/--list to see options.")

    elif args.command == 'forge':
        if (args.payload and args.token) or (not args.payload and not args.token):
            print("[!] Provide either -p/--payload or -t/--token.")
            return
        forge.forge_jwt(
            alg=args.alg,
            payload_str=args.payload,
            token=args.token,
            secret=args.secret,
            privkey_path=args.privkey,
            kid=args.kid,
        )

    elif args.command == 'brute':
        bruteforce.bruteforce_hmac_secret(args.token, args.wordlist)

    elif args.command == 'update':
        update_jwtek()

    else:
        parser_cli.print_help()

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 1:
        # Show full CLI help if no args passed
        main(['-h'])
    else:
        main()

