import argparse
from core import parser, static_analysis, brute_forcer, exploits, validator, forge, audit, smuggle

def main():
    parser_cli = argparse.ArgumentParser(
        prog='jwtek',
        description="🛡️ JWTEK: JWT Security Analysis & Exploitation Tool"
    )

    subparsers = parser_cli.add_subparsers(dest='command', help='Available commands')

    # === analyze ===
    analyze_parser = subparsers.add_parser('analyze', help='Static (or optional RS256) analysis of a JWT')
    analyze_parser.add_argument('--token', required=True, help='JWT string to analyze')
    analyze_parser.add_argument('--pubkey', help='Optional path to public key (PEM) for signature verification')
    analyze_parser.add_argument('--audit', action='store_true', help='Audit JWT claims for privilege abuse')

    # === brute-force ===
    brute_parser = subparsers.add_parser('brute-force', help='Brute-force JWT secret for HS256')
    brute_parser.add_argument('--token', required=True, help='JWT token to crack')
    brute_parser.add_argument('--wordlist', required=True, help='Path to wordlist file or preset name')

    # === exploit ===
    exploit_parser = subparsers.add_parser('exploit', help='Show exploitation guidance')
    exploit_parser.add_argument('--vuln', help='Vulnerability ID (e.g., alg-none)')
    exploit_parser.add_argument('--secret', help='Optional secret key (for PoC or bypass)')
    exploit_parser.add_argument('--url', help='Target URL for bypass testing')
    exploit_parser.add_argument('--poc', action='store_true', help='Generate PoC token')
    exploit_parser.add_argument('--bypass', action='store_true', help='Attempt authentication bypass using token')
    exploit_parser.add_argument('--list', action='store_true', help='List available vulnerability IDs')

    # === forge ===
    forge_parser = subparsers.add_parser('forge', help="Forge a custom JWT token")
    forge_parser.add_argument('--alg', required=True, help="Algorithm to use (HS256, RS256, none)")
    forge_parser.add_argument('--payload', required=True, help="JSON payload string")
    forge_parser.add_argument('--secret', help="Secret key for HS256 (optional)")
    forge_parser.add_argument('--pubkey', help='Path to RSA public key (for RS256)')
    forge_parser.add_argument('--privkey', help='Path to RSA private key (for RS256)')

    # === smuggle ===
    smuggle_parser = subparsers.add_parser('smuggle', help='Compare two JWTs for tampering or smuggling')
    smuggle_parser.add_argument('--token1', required=True, help='Original JWT')
    smuggle_parser.add_argument('--token2', required=True, help='Potentially tampered JWT')
    smuggle_parser.add_argument("--o", help="Output path to save the comparison report")

    args = parser_cli.parse_args()

    if args.command == 'analyze':
        token = args.token
        header, payload, signature = parser.decode_jwt(token)

        if not header or not payload:
            print("[!] Could not decode JWT. Check if the format is valid.")
            return

        parser.pretty_print_jwt(header, payload, signature)
        static_analysis.run_all_checks(header, payload)

        if args.pubkey:
            validator.verify_signature_rs256(token, args.pubkey)

        if args.audit:
            audit.audit_claims(payload)

    elif args.command == 'brute-force':
        token = args.token
        wordlist = args.wordlist
        brute_forcer.brute_force_hs256(token, wordlist)

    elif args.command == 'exploit':
        if args.list:
            exploits.list_available_exploits()
        elif args.vuln:
            if args.poc:
                exploits.generate_poc_token(args.vuln, secret=args.secret)
            elif args.bypass:
                if not args.secret or not args.url:
                    print("[!] --secret and --url are required for bypass testing.")
                else:
                    exploits.attempt_bypass(args.vuln, args.secret, args.url)
            else:
                exploits.explain_exploit(args.vuln, secret=args.secret)
        else:
            print("[!] Use --vuln to specify a vulnerability ID or --list to see options.")

    elif args.command == 'forge':
        forge.forge_jwt(
            alg=args.alg,
            payload_str=args.payload,
            secret=args.secret,
            privkey_path=args.privkey
        )

    elif args.command == 'smuggle':
        smuggle.smuggle_compare(args.token1, args.token2, args.o)

    else:
        parser_cli.print_help()

if __name__ == '__main__':
    main()