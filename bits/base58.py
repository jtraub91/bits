"""
Base58 encoding
"""
from typing import Tuple

BITCOIN_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BITCOIN_ALPHABET_MAP = {value: idx for idx, value in enumerate(BITCOIN_ALPHABET)}


def base58encode(data: bytes) -> bytes:
    # refactored from https://github.com/trezor/python-mnemonic and
    # https://github.com/keis/base58
    # oddly, https://digitalbazaar.github.io/base58-spec/#encode doesn't seem to work
    origlen = len(data)
    data = data.lstrip(b"\x00")
    newlen = len(data)
    zeros = origlen - newlen

    encoded = b""
    integer = int.from_bytes(data, "big")
    while integer:
        integer, idx = divmod(integer, 58)
        encoded = BITCOIN_ALPHABET[idx : idx + 1] + encoded
    return BITCOIN_ALPHABET[0:1] * zeros + encoded


def base58check(version: bytes, payload: bytes) -> bytes:
    """
    Base58 check encoding used for bitcoin addresses
    # https://en.bitcoin.it/wiki/Base58Check_encoding
    Args:
        version: bytes, 0x00 for mainnet, 0x6f for testnet, etc.
        payload: bytes, payload, e.g. pubkey hash
    """
    checksum = hashlib.sha256(hashlib.sha256(version + payload).digest()).digest()[:4]
    return base58encode(version + payload + checksum)


def base58decode(data: bytes) -> bytes:
    origlen = len(data)
    data = data.lstrip(b"1")
    newlen = len(data)
    ones = origlen - newlen

    result = 0
    for idx, byte in enumerate(reversed(data)):
        result += BITCOIN_ALPHABET_MAP[byte] * (58**idx)

    decoded = b""
    while result:
        result, byte = divmod(result, 256)
        decoded = byte.to_bytes(1, "big") + decoded
    return b"\0" * ones + decoded


def base58check_decode(addr_: bytes) -> bytes:
    """
    Returns:
        (version: int, payload: bytes)
    """
    decoded_addr = base58decode(addr_)
    payload = decoded_addr[:-4]
    checksum = decoded_addr[-4:]
    checksum_check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    assert checksum == checksum_check
    return payload
