import argparse
from core import parser, static_analysis, brute_forcer, exploits, validator

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

    # === brute-force ===
    brute_parser = subparsers.add_parser('brute-force', help='Brute-force JWT secret for HS256')
    brute_parser.add_argument('--token', required=True, help='JWT token to crack')
    brute_parser.add_argument('--wordlist', required=True, help='Path to wordlist file or preset name')

    # === exploit ===
    exploit_parser = subparsers.add_parser('exploit', help='Show exploitation guidance')
    exploit_parser.add_argument('--vuln', help='Vulnerability ID (e.g., alg-none)')
    exploit_parser.add_argument('--secret', help='Optional secret key if needed')
    exploit_parser.add_argument('--list', action='store_true', help='List available vulnerability IDs')

    args = parser_cli.parse_args()

    if args.command == 'analyze':
        token = args.token
        header, payload, signature = parser.decode_jwt(token)

        if not header or not payload:
            print("[!] Could not decode JWT. Check if the format is valid.")
            return

        # Show header, payload, and base64 signature
        parser.pretty_print_jwt(header, payload, signature)

        # Static checks
        static_analysis.run_all_checks(header, payload)

        # Optional RS256 signature validation
        if args.pubkey:
            validator.verify_signature_rs256(token, args.pubkey)

    elif args.command == 'brute-force':
        token = args.token
        wordlist = args.wordlist
        brute_forcer.brute_force_hs256(token, wordlist)

    elif args.command == 'exploit':
        if args.list:
            exploits.list_available_exploits()
        elif args.vuln:
            exploits.explain_exploit(args.vuln, secret=args.secret)
        else:
            print("[!] Use --vuln to specify a vulnerability ID or --list to see options.")

    else:
        parser_cli.print_help()

if __name__ == '__main__':
    main()
