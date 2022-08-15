import hashlib
from base58 import b58encode, b58decode


def pubkey(x: int, y: int, compressed=False) -> bytes:
    """
    Returns pubkey from point (x, y) as hex bytes, optionally compressed
    """
    if compressed:
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return prefix + x.to_bytes(32, "big")
    else:
        prefix = b"\x04"
        return prefix + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def pubkey_hash(pubkey_: bytes) -> bytes:
    """
    Returns pubkeyhash as used in P2PKH scriptPubKey
    e.g. RIPEMD160(SHA256(pubkey_))
    """
    hash_256 = hashlib.sha256(pubkey_).digest()
    ripe_hash = hashlib.new("ripemd160", hash_256).digest()
    return ripe_hash


def bitcoin_address(pk_hash: bytes, version: bytes = b"\x00") -> bytes:
    """
    Returns bitcoin address from public key hash

    Args:
        version: 0x00 for mainnet, 0x6f for testnet
    """
    version_pkh = version + pk_hash
    checksum = hashlib.sha256(hashlib.sha256(version_pkh).digest()).digest()[:4]
    return b58encode(version_pkh + checksum)


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
