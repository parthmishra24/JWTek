import argparse
from jwtek.core import (
    parser,
    static_analysis,
    exploits,
    validator,
    forge,
    updater,
    audit,
    extractor,
    ui,
)

def analyze_all_from_file(file_path, pubkey=None, jwks_url=None, audit_flag=False, output_json=None):
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

def main(argv=None):
    parser_cli = argparse.ArgumentParser(
        prog='jwtek',
        description="🛡️ JWTEK: JWT Security Analysis & Exploitation Tool"
    )
    parser_cli.add_argument('--no-color', action='store_true', help='Disable colored output')

    subparsers = parser_cli.add_subparsers(dest='command', help='Available commands')

    # === analyze ===
    analyze_parser = subparsers.add_parser('analyze', help='Static (or optional RS256) analysis of a JWT')
    analyze_parser.add_argument('--token', required=False, help='JWT string to analyze')
    analyze_parser.add_argument('--pubkey', help='Optional path to public key (PEM) for signature verification')
    analyze_parser.add_argument('--jwks', help='URL to JWKS for signature verification')
    analyze_parser.add_argument('--audit', action='store_true', help='Audit JWT claims for privilege abuse')
    analyze_parser.add_argument('--file', help='Path to file to extract JWT from')
    analyze_parser.add_argument('--analyze-all', action='store_true', help='Extract and analyze all JWTs from file')
    analyze_parser.add_argument('--json-out', help='Write analysis results to JSON file')

    # === exploit ===
    exploit_parser = subparsers.add_parser('exploit', help='Show exploitation guidance')
    exploit_parser.add_argument('--vuln', help='Vulnerability ID (e.g., alg-none)')
    exploit_parser.add_argument('--secret', help='Optional secret key (for PoC or bypass)')
    exploit_parser.add_argument('--url', help='Target URL for bypass testing')
    exploit_parser.add_argument('--jwks', help='JWKS URL to fetch key for certain exploits')
    exploit_parser.add_argument('--poc', action='store_true', help='Generate PoC token')
    exploit_parser.add_argument('--bypass', action='store_true', help='Attempt authentication bypass using token')
    exploit_parser.add_argument('--list', action='store_true', help='List available vulnerability IDs')

    # === forge ===
    forge_parser = subparsers.add_parser('forge', help="Forge a custom JWT token")
    forge_parser.add_argument('--alg', required=True, help="Algorithm to use (HS256, RS256, ES256, PS256, none)")
    forge_parser.add_argument('--payload', required=True, help="JSON payload string")
    forge_parser.add_argument('--secret', help="Secret key for HS256 (optional)")
    forge_parser.add_argument('--pubkey', help='Path to RSA public key (for RS256)')
    forge_parser.add_argument('--privkey', help='Path to RSA private key (for RS256/ES256/PS256)')
    forge_parser.add_argument('--kid', help='Optional kid header value')

    # === update ===
    update_parser = subparsers.add_parser('update', help='Update JWTEK from GitHub')

    args = parser_cli.parse_args()
    if getattr(args, 'no_color', False):
        ui.set_no_color(True)
    token = None

    if args.command == 'analyze':

        if getattr(args, 'analyze_all', False) and getattr(args, 'file', None):
            analyze_all_from_file(
                args.file,
                pubkey=args.pubkey,
                jwks_url=args.jwks,
                audit_flag=args.audit,
                output_json=args.json_out,
            )
            return

        token = getattr(args, 'token', None)

        # 🔍 If no token is provided, try extracting from file
        if not token and getattr(args, 'file', None):
            token = extractor.extract_from_file(args.file)
            if not token:
                print("[!] No valid JWT found in file.")
                return
            else:
                print(f"[+] Extracted JWT:\n{token}\n")

        if not token:
            print("[!] Please provide a JWT token using --token or extract it using --file.")
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
                    print("[!] --url is required for bypass testing.")
                else:
                    exploits.attempt_bypass(args.vuln, args.secret or "", args.url, jwks_url=args.jwks)
            else:
                exploits.explain_exploit(args.vuln, secret=args.secret)
        else:
            print("[!] Use --vuln to specify a vulnerability ID or --list to see options.")

    elif args.command == 'forge':
        forge.forge_jwt(
            alg=args.alg,
            payload_str=args.payload,
            secret=args.secret,
            privkey_path=args.privkey,
            kid=args.kid,
        )

    elif args.command == 'update':
        updater.update_tool(repo_url=args.repo, branch=args.branch)
    else:
        parser_cli.print_help()

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 1:
        # Show full CLI help if no args passed
        main(['--help'])
    else:
        main()

