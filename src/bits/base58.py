"""
Base58(check) encoding / decoding
"""
import hashlib
from typing import Tuple

BITCOIN_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BITCOIN_ALPHABET_MAP = {value: idx for idx, value in enumerate(BITCOIN_ALPHABET)}


def base58encode(data: bytes) -> bytes:
    """
    Encode data in base58 format
    Args:
        data: bytes, data to encode
    Returns:
        base58 encoded data

    >>> base58encode(b"hello world")
    b'StV1DL6CwTryKyV'
    """
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


def base58check(data: bytes) -> bytes:
    """
    Encode data as base58check encoding used in Bitcoin addresses
    # https://en.bitcoin.it/wiki/Base58Check_encoding
    Args:
        data: bytes, data to encode
    Returns:
        base58check encoded data

    >>> base58check(b"hello world")
    b'3vQB7B6MrGQZaxCuFg4oh'
    """
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return base58encode(data + checksum)


def base58decode(data: bytes) -> bytes:
    """
    Decode base58 encoded data
    Args:
        data: bytes, data to decode
    Returns:
        decoded data

    >>> base58decode(b"StV1DL6CwTryKyV")
    b'hello world'
    """
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
    Decode base58check encoded data
    Args:
        data: bytes, data to decode
    Returns:
        decoded data

    >>> base58check_decode(b"3vQB7B6MrGQZaxCuFg4oh")
    b'hello world'
    """
    decoded_addr = base58decode(addr_)
    payload = decoded_addr[:-4]
    checksum = decoded_addr[-4:]
    checksum_check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != checksum_check:
        raise ValueError("invalid checksum")
    return payload


def is_base58check(data: bytes):
    """
    Check if data is base58check encoded
    Args:
        data: bytes, data to check
    Returns:
        True if base58check encoded, else False

    >>> is_base58check(b"DthHcFYf2SzzprfBcpKfTG")
    True
    >>> is_base58check(b"2yGEbwRFyhPZZckJm")
    False
    """
    try:
        base58check_decode(data)
        return True
    except Exception:
        return False
