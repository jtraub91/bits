import hashlib
from typing import Tuple

from base58 import b58decode
from base58 import b58encode
from ecdsa import SECP256k1
from ecdsa import SigningKey
from ecdsa import VerifyingKey


def pubkey(x: int, y: int, compressed=False) -> bytes:
    """
    Returns pubkey in hex from point (x, y),
    optionally SEC1 compressed
    """
    if compressed:
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return prefix + x.to_bytes(32, "big")
    else:
        prefix = b"\x04"
        return prefix + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def pubkey_from_pem(pem: bytes, compressed=False) -> bytes:
    vk = VerifyingKey.from_pem(pem)
    return pubkey(vk.pubkey.point.x(), vk.pubkey.point.y(), compressed=compressed)


def point(pubkey_: bytes) -> Tuple[int]:
    """
    Return (x, y) from pubkey_ bytes encoding
    """
    vk = VerifyingKey.from_string(pubkey_, curve=SECP256k1)
    return vk.pubkey.point.x(), vk.pubkey.point.y()


def point_from_pubkey(pubkey_: bytes) -> Tuple[int]:
    """
    WIP
    """
    if pubkey_[0] not in [b"\x02", b"\x03", b"\x04"]:
        raise ValueError(f"unrecognized version byte: {pubkey_[0]}")
    x = int.from_bytes(pubkey_[1:33], "big")
    if pubkey_[0] == b"\x02":
        pass
    elif pubkey_[0] == b"\x03":
        pass
    else:
        # uncompressed
        x = int.from_bytes(pubkey_[1:33], "big")
        y = int.from_bytes(pubkey_[33:], "big")
    return (x, y)


def pubkey_hash(pubkey_: bytes) -> bytes:
    """
    Returns pubkeyhash as used in P2PKH scriptPubKey
    e.g. RIPEMD160(SHA256(pubkey_))
    """
    hash_256 = hashlib.sha256(pubkey_).digest()
    ripe_hash = hashlib.new("ripemd160", hash_256).digest()
    return ripe_hash


def base58check(version: bytes, payload: bytes) -> bytes:
    """
    Base58 check encoding used for bitcoin addresses

    Args:
        version: 0x00 for mainnet, 0x6f for testnet, etc.
        payload
    """
    version_payload = version + payload
    checksum = hashlib.sha256(hashlib.sha256(version_payload).digest()).digest()[:4]
    return b58encode(version_payload + checksum)


def compact_size_uint(integer: int) -> bytes:
    """
    https://developer.bitcoin.org/reference/transactions.html#compactsize-unsigned-integers
    """
    if integer < 0:
        raise ValueError("signed integer")
    elif integer >= 0 and integer <= 252:
        return integer.to_bytes(1, "little")
    elif integer >= 253 and integer <= 0xFFFF:
        return b"\xfd" + integer.to_bytes(2, "little")
    elif integer >= 0x10000 and integer <= 0xFFFFFFFF:
        return b"\xfe" + integer.to_bytes(4, "little")
    elif integer >= 0x100000000 and integer <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + integer.to_bytes(8, "little")


def parse_compact_size_uint(payload: bytes) -> Tuple[int, bytes]:
    """
    This function expects a compact size uint at the beginning of payload.
    Since compact size uints are variable in size, this function
    will observe the first byte, parse the necessary subsequent bytes,
    and return, as a tuple, the parsed integer followed by the rest of the
    payload (i.e. the remaining unparsed payload)
    """
    first_byte = payload[0]
    if first_byte == 255:
        integer = int.from_bytes(payload[1:9], "little")
        payload = payload[9:]
    elif first_byte == 254:
        integer = int.from_bytes(payload[1:5], "little")
        payload = payload[5:]
    elif first_byte == 253:
        integer = int.from_bytes(payload[1:3], "little")
        payload = payload[3:]
    else:
        integer = first_byte
        payload = payload[1:]
    return integer, payload


def pub_point(priv_: int) -> Tuple[int]:
    """
    Return (x, y) public point on SECP256k1 curve, from priv_ key
    """
    sk = SigningKey.from_secret_exponent(priv_, curve=SECP256k1)
    return sk.verifying_key.pubkey.point.x(), sk.verifying_key.pubkey.point.y()


def d_hash(msg: bytes) -> bytes:
    """
    Double sha256 hash of msg
    """
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def pubkey_hash_from_p2pkh(baddr: bytes) -> bytes:
    """
    Return pubkeyhash from bitcoin address, with checksum verification
    """
    decoded_addr = b58decode(baddr)
    checksum = decoded_addr[-4:]
    checksum_check = hashlib.sha256(hashlib.sha256(decoded_addr[:-4]).digest()).digest()
    assert checksum == checksum_check[:4]
    return decoded_addr[1:-4]  # remove version byte and checksum


def to_bitcoin_address(pubkey_: bytes, network: str = None) -> str:
    """
    Convert pubkey to bitcoin address
    Args:
        pubkey_: bytes, pubkey in hex
        network: str, `mainnet` or `testnet`
    Returns:
        base58 encoded bitcoin address
    """
    pkh = pubkey_hash(pubkey_)
    if network == "mainnet":
        version = b"\x00"
    elif network == "testnet":
        version = b"\x6f"
    else:
        raise ValueError(f"unrecognized network: {network}")
    return base58check(version, pkh).decode("ascii")
