import base64
import copy
import json
import jwt

from . import ui, parser


def forge_jwt(
    alg,
    payload_str=None,
    token=None,
    secret=None,
    privkey_path=None,
    kid=None,
    header_dict=None,
    payload_dict=None,
    signature=None,
):
    header_from_token = None
    payload = None

    if token:
        header_from_token, payload_from_token, _ = parser.decode_jwt(token)
        if not header_from_token or not payload_from_token:
            ui.error("Invalid token format. Could not decode.")
            return
        payload = payload_from_token

    if payload_dict is not None:
        payload = copy.deepcopy(payload_dict)
    elif payload is None:
        if payload_str is None:
            ui.error("Payload JSON or token is required.")
            return
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            ui.error("Invalid payload format. Must be valid JSON.")
            return

    if header_dict is not None:
        header = copy.deepcopy(header_dict)
    elif header_from_token is not None:
        header = header_from_token
    else:
        header = {}

    if header_dict is None and "typ" not in header:
        header["typ"] = "JWT"
    header["alg"] = alg

    if kid:
        header["kid"] = kid

    if alg == "none":
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature_value = "" if signature is None else signature
        forged_token = f"{header_b64}.{payload_b64}.{signature_value}"
        ui.success("\n[+] Forged JWT (alg=none):")
        print(forged_token)
        return

    elif alg == "HS256":
        if not secret:
            ui.error("HS256 requires -secret to sign the token.")
            return
        token = jwt.encode(payload, secret, algorithm="HS256", headers=header)
        ui.success("\n[+] Forged JWT (HS256):")
        print(token)
        return

    elif alg in {"RS256", "ES256", "PS256"}:
        if not privkey_path:
            ui.error("{} requires -privkey path to sign the token.".format(alg))
            return
        try:
            with open(privkey_path, "r") as f:
                private_key = f.read()
        except Exception as e:
            ui.error(f"Failed to read private key: {e}")
            return
        token = jwt.encode(payload, private_key, algorithm=alg, headers=header)
        ui.success(f"\n[+] Forged JWT ({alg}):")
        print(token)
        return

    else:
        ui.error(f"Unsupported algorithm: {alg}")


def _format_value(value):
    try:
        return json.dumps(value)
    except TypeError:
        return repr(value)


def _coerce_value(raw_value):
    if raw_value == "":
        return raw_value
    try:
        return json.loads(raw_value)
    except json.JSONDecodeError:
        trimmed = raw_value.strip()
        if trimmed == "":
            return ""
        try:
            return json.loads(trimmed)
        except json.JSONDecodeError:
            return raw_value


def _parse_field_selection(selection, keys):
    selected = []
    tokens = [part.strip() for part in selection.split(",") if part.strip()]
    for token in tokens:
        if token.isdigit():
            idx = int(token)
            if 1 <= idx <= len(keys):
                key = keys[idx - 1]
                if key not in selected:
                    selected.append(key)
            else:
                ui.warn(f"Ignoring invalid index: {token}")
        else:
            matches = [k for k in keys if k.lower() == token.lower()]
            if matches:
                key = matches[0]
                if key not in selected:
                    selected.append(key)
            else:
                ui.warn(f"Unknown field: {token}")
    return selected


def _edit_mapping(section_name, data):
    if not data:
        ui.warn(f"No fields available in {section_name.lower()} to edit.")
        return

    print(f"\nAvailable {section_name} fields:")
    keys = list(data.keys())
    for idx, key in enumerate(keys, start=1):
        print(f"  {idx}. {key}: {_format_value(data[key])}")

    selection = input(
        f"Select {section_name.lower()} field(s) to edit (comma separated, or press Enter to cancel): "
    ).strip()

    if not selection:
        ui.info("No fields selected.")
        return

    chosen_keys = _parse_field_selection(selection, keys)
    if not chosen_keys:
        ui.warn("No valid fields were selected.")
        return

    for key in chosen_keys:
        current_val = _format_value(data[key])
        new_val = input(
            f"Enter new value for {section_name} '{key}' (current: {current_val}). Leave blank to keep unchanged: "
        )
        if new_val == "":
            ui.info(f"{key} unchanged.")
            continue
        data[key] = _coerce_value(new_val)
        ui.success(f"Updated {section_name} '{key}'.")


def _normalize_algorithm(value):
    if isinstance(value, str):
        upper = value.upper()
        return "none" if upper == "NONE" else upper
    return str(value)


def interactive_edit(header, payload, signature):
    working_header = copy.deepcopy(header)
    working_payload = copy.deepcopy(payload)
    current_signature = signature

    ui.section("JWT Edit Mode")
    ui.info("Modify fields and forge a new token with your changes.")

    algorithm = _normalize_algorithm(working_header.get("alg", "none"))
    working_header["alg"] = algorithm

    while True:
        print("\nSections available to edit:")
        sections = [("1", "Header"), ("2", "Payload")]
        if algorithm == "none":
            sections.append(("3", "Signature"))

        for key, label in sections:
            print(f"  {key}. {label}")
        print("  done. Finish editing")

        choice = input("Choose a section to edit: ").strip().lower()

        if choice in {"done", "q", "quit"}:
            break
        elif choice in {"1", "header", "h"}:
            _edit_mapping("Header", working_header)
            algorithm = _normalize_algorithm(working_header.get("alg", algorithm))
            working_header["alg"] = algorithm
        elif choice in {"2", "payload", "p"}:
            _edit_mapping("Payload", working_payload)
        elif choice in {"3", "signature", "s"} and algorithm == "none":
            new_sig = input(
                "Enter new signature value (blank keeps current): "
            )
            if new_sig == "":
                ui.info("Signature unchanged.")
            else:
                current_signature = new_sig
                ui.success("Signature updated.")
        else:
            ui.warn("Invalid selection. Please choose header, payload, signature, or done.")
            continue

        continue_choice = input("Edit another section? (y/N): ").strip().lower()
        if continue_choice != "y":
            break

    confirm = input("Forge JWT with the updated data? (y/N): ").strip().lower()
    if confirm != "y":
        ui.info("Aborted forging. No token was generated.")
        return

    if algorithm == "HS256":
        secret = input("Enter secret key for HS256 signing: ").strip()
        if not secret:
            ui.error("Secret key is required to forge HS256 tokens.")
            return
        forge_jwt(
            "HS256",
            secret=secret,
            header_dict=working_header,
            payload_dict=working_payload,
        )
    elif algorithm in {"RS256", "ES256", "PS256"}:
        privkey_path = input(f"Path to private key for {algorithm} signing: ").strip()
        if not privkey_path:
            ui.error(f"Private key path is required for {algorithm} tokens.")
            return
        forge_jwt(
            algorithm,
            privkey_path=privkey_path,
            header_dict=working_header,
            payload_dict=working_payload,
        )
    elif algorithm == "none":
        forge_jwt(
            "none",
            header_dict=working_header,
            payload_dict=working_payload,
            signature=current_signature,
        )
    else:
        ui.error(f"Unsupported algorithm for forging: {algorithm}")
