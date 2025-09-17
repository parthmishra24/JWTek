"""Utilities for converting JSON Web Keys (JWK/JWKS) into PEM files.

This module focuses on the common need to take a JWKS document – often
returned by an identity provider – and extract the contained RSA public keys as
PEM encoded files so they can be used with tooling that expects the PEM format.
"""

from __future__ import annotations

import json
import textwrap
from base64 import b64encode, urlsafe_b64decode
from pathlib import Path
from typing import List


class JWKSConversionError(Exception):
    """Raised when a JWKS document cannot be converted into PEM keys."""


def _ensure_dir(path: Path) -> None:
    """Create *path* as a directory if it does not already exist."""

    if path.exists() and not path.is_dir():
        raise JWKSConversionError(f"{path} exists and is not a directory")
    path.mkdir(parents=True, exist_ok=True)


def _b64_to_int(data: str) -> int:
    """Decode a base64url encoded integer."""

    padding = "=" * (-len(data) % 4)
    decoded = urlsafe_b64decode(data + padding)
    return int.from_bytes(decoded, "big")


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])

    encoded: list[int] = []
    value = length
    while value > 0:
        encoded.append(value & 0xFF)
        value >>= 8

    return bytes([0x80 | len(encoded)]) + bytes(reversed(encoded))


def _encode_integer(value: int) -> bytes:
    if value < 0:
        raise JWKSConversionError("Negative integers are not supported")

    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw

    return b"\x02" + _encode_length(len(raw)) + raw


def _encode_sequence(parts: List[bytes]) -> bytes:
    body = b"".join(parts)
    return b"\x30" + _encode_length(len(body)) + body


def _encode_base128(value: int) -> bytes:
    if value == 0:
        return b"\x00"

    pieces: list[int] = []
    while value > 0:
        pieces.append(value & 0x7F)
        value >>= 7

    encoded = bytearray()
    for piece in reversed(pieces):
        encoded.append(piece | 0x80)
    encoded[-1] &= 0x7F
    return bytes(encoded)


def _encode_object_identifier(oid: tuple[int, ...]) -> bytes:
    if len(oid) < 2:
        raise JWKSConversionError("OID must contain at least two components")

    first = 40 * oid[0] + oid[1]
    body = bytes([first]) + b"".join(_encode_base128(x) for x in oid[2:])
    return b"\x06" + _encode_length(len(body)) + body


def _encode_null() -> bytes:
    return b"\x05\x00"


def _encode_bit_string(data: bytes) -> bytes:
    return b"\x03" + _encode_length(len(data) + 1) + b"\x00" + data


def _pem_wrap(der_bytes: bytes) -> bytes:
    base64_body = b64encode(der_bytes).decode("ascii")
    wrapped = "\n".join(textwrap.wrap(base64_body, 64))
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        + wrapped
        + "\n-----END PUBLIC KEY-----\n"
    ).encode("ascii")


def _rsa_pem_from_jwk(jwk: dict) -> bytes:
    """Return PEM encoded RSA public key from *jwk*."""

    try:
        n = _b64_to_int(jwk["n"])
        e = _b64_to_int(jwk["e"])
    except KeyError as exc:  # pragma: no cover - defensive guard
        missing = exc.args[0]
        raise JWKSConversionError(f"RSA JWK missing required parameter: {missing}") from exc

    rsa_sequence = _encode_sequence([
        _encode_integer(n),
        _encode_integer(e),
    ])

    algorithm_identifier = _encode_sequence([
        _encode_object_identifier((1, 2, 840, 113549, 1, 1, 1)),
        _encode_null(),
    ])

    spki = _encode_sequence([
        algorithm_identifier,
        _encode_bit_string(rsa_sequence),
    ])

    return _pem_wrap(spki)


def _jwk_to_pem(jwk: dict) -> bytes:
    """Convert a single JWK dictionary to PEM encoded bytes."""

    kty = jwk.get("kty")
    if kty == "RSA":
        return _rsa_pem_from_jwk(jwk)
    raise JWKSConversionError(f"Unsupported key type: {kty}")


def _sanitize_filename(name: str) -> str:
    """Return a filesystem friendly version of *name*."""

    safe = [c if c.isalnum() or c in ("-", "_") else "-" for c in name]
    sanitized = "".join(safe).strip("-")
    return sanitized or "key"


def _determine_output_path(
    base_output: Path | None,
    jwks_path: Path,
    key_identifier: str,
    multiple_keys: bool,
) -> Path:
    """Return output path for a key based on provided options."""

    filename = f"{_sanitize_filename(key_identifier)}.pem"

    if base_output is None:
        return jwks_path.with_name(filename)

    if base_output.exists():
        if base_output.is_dir():
            return base_output / filename
        if multiple_keys:
            raise JWKSConversionError("Cannot write multiple keys to a single PEM file")
        return base_output

    # Path does not exist yet
    if base_output.suffix:  # looks like a file
        if multiple_keys:
            raise JWKSConversionError("Cannot write multiple keys to a single PEM file")
        parent = base_output.parent
        if parent and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        return base_output

    # treat as directory
    _ensure_dir(base_output)
    return base_output / filename


def convert_jwks_to_pem(
    jwks_path: str | Path,
    output_path: str | Path | None = None,
) -> List[Path]:
    """Convert keys from *jwks_path* into PEM files.

    Parameters
    ----------
    jwks_path:
        Path to a JWKS (JSON Web Key Set) document on disk.
    output_path:
        Optional directory or file path to place the converted PEM files.  If a
        directory is supplied, each key is saved as ``<kid>.pem`` inside that
        directory.  If a file path is provided the JWKS must contain exactly one
        key, which is written to the specified file.

    Returns
    -------
    list[pathlib.Path]
        The paths of the PEM files that were written.
    """

    jwks_path = Path(jwks_path)
    if not jwks_path.is_file():
        raise JWKSConversionError(f"JWKS file not found: {jwks_path}")

    with jwks_path.open("r", encoding="utf-8") as fh:
        try:
            jwks = json.load(fh)
        except json.JSONDecodeError as exc:
            raise JWKSConversionError("Invalid JWKS JSON") from exc

    keys = list(jwks.get("keys") or [])
    if not keys:
        raise JWKSConversionError("JWKS does not contain any keys")

    base_output = Path(output_path) if output_path is not None else None
    if base_output is not None and not base_output.exists() and not base_output.suffix:
        _ensure_dir(base_output)

    written_paths: List[Path] = []
    multiple = len(keys) > 1

    for index, jwk in enumerate(keys):
        kid = jwk.get("kid") or f"key-{index}"
        pem_bytes = _jwk_to_pem(jwk)
        target_path = _determine_output_path(base_output, jwks_path, kid, multiple)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(pem_bytes)
        written_paths.append(target_path)

    return written_paths

