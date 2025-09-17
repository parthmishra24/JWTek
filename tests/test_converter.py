import json
from base64 import b64decode, urlsafe_b64encode

import pytest

from jwtek.__main__ import main
from jwtek.core import converter


MODULUS_ONE = int(
    "0xc7f1d2e3a4b5968778695a4b3c2d1e0f112233445566778899aabbccddeeff00"
    "fedcba98765432100123456789abcdef112233445566778899aabbccddeeff11",
    16,
)
MODULUS_TWO = int(
    "0xd5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4"
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    16,
)
EXPONENT = 65537


def _to_b64(number: int) -> str:
    length = (number.bit_length() + 7) // 8
    return (
        urlsafe_b64encode(number.to_bytes(length, "big"))
        .rstrip(b"=")
        .decode("ascii")
    )


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset

    num_octets = first & 0x7F
    length = int.from_bytes(data[offset:offset + num_octets], "big")
    offset += num_octets
    return length, offset


def _read_tlv(expected_tag: int, data: bytes, offset: int) -> tuple[bytes, int]:
    tag = data[offset]
    if tag != expected_tag:  # pragma: no cover - defensive guard
        raise AssertionError(f"Unexpected tag: {tag:#x}")

    length, offset = _read_length(data, offset + 1)
    value = data[offset:offset + length]
    offset += length
    return value, offset


def _extract_public_numbers(pem_bytes: bytes) -> tuple[int, int]:
    lines = [
        line.strip()
        for line in pem_bytes.decode("ascii").splitlines()
        if line and not line.startswith("-----")
    ]
    der = b64decode("".join(lines))

    spki, consumed = _read_tlv(0x30, der, 0)
    assert consumed == len(der)

    alg, offset = _read_tlv(0x30, spki, 0)
    # we do not inspect the algorithm identifier beyond ensuring it parses
    assert offset <= len(spki)
    bit_string, offset = _read_tlv(0x03, spki, offset)
    assert offset == len(spki)
    assert bit_string[0] == 0

    rsa_sequence, consumed = _read_tlv(0x30, bit_string[1:], 0)
    assert consumed == len(bit_string) - 1

    modulus_bytes, seq_offset = _read_tlv(0x02, rsa_sequence, 0)
    exponent_bytes, seq_offset = _read_tlv(0x02, rsa_sequence, seq_offset)
    assert seq_offset == len(rsa_sequence)

    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(exponent_bytes, "big")
    return modulus, exponent


def _jwks_for_key(kid: str, modulus: int) -> dict:
    return {
        "kty": "RSA",
        "kid": kid,
        "n": _to_b64(modulus),
        "e": _to_b64(EXPONENT),
    }


def test_convert_single_jwk_to_specific_file(tmp_path):
    jwk = _jwks_for_key("kid1", MODULUS_ONE)
    jwks_file = tmp_path / "jwks.json"
    jwks_file.write_text(json.dumps({"keys": [jwk]}), encoding="utf-8")

    output_file = tmp_path / "public.pem"
    written = converter.convert_jwks_to_pem(jwks_file, output_file)
    assert written == [output_file]

    modulus, exponent = _extract_public_numbers(output_file.read_bytes())
    assert modulus == MODULUS_ONE
    assert exponent == EXPONENT

    cli_output = tmp_path / "cli.pem"
    main(['convert', '-i', str(jwks_file), '-o', str(cli_output)])
    assert cli_output.exists()
    cli_modulus, cli_exponent = _extract_public_numbers(cli_output.read_bytes())
    assert cli_modulus == MODULUS_ONE
    assert cli_exponent == EXPONENT


def test_convert_multiple_keys_to_directory(tmp_path):
    jwk_one = _jwks_for_key("kid one", MODULUS_ONE)
    jwk_two = _jwks_for_key("kid/two", MODULUS_TWO)
    jwks_file = tmp_path / "multi.json"
    jwks_file.write_text(json.dumps({"keys": [jwk_one, jwk_two]}), encoding="utf-8")

    output_dir = tmp_path / "output"
    written_paths = converter.convert_jwks_to_pem(jwks_file, output_dir)
    assert len(written_paths) == 2

    expected_one = output_dir / "kid-one.pem"
    expected_two = output_dir / "kid-two.pem"
    assert set(written_paths) == {expected_one, expected_two}

    mod_one, exp_one = _extract_public_numbers(expected_one.read_bytes())
    mod_two, exp_two = _extract_public_numbers(expected_two.read_bytes())
    assert mod_one == MODULUS_ONE
    assert exp_one == EXPONENT
    assert mod_two == MODULUS_TWO
    assert exp_two == EXPONENT


def test_multiple_keys_to_single_file_raises(tmp_path):
    jwk_one = _jwks_for_key("a", MODULUS_ONE)
    jwk_two = _jwks_for_key("b", MODULUS_TWO)
    jwks_file = tmp_path / "double.json"
    jwks_file.write_text(json.dumps({"keys": [jwk_one, jwk_two]}), encoding="utf-8")

    with pytest.raises(converter.JWKSConversionError):
        converter.convert_jwks_to_pem(jwks_file, tmp_path / "single.pem")
