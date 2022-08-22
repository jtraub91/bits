import hashlib

from base58 import b58decode
from base58 import b58encode
from ecdsa import SECP256k1
from ecdsa import SigningKey


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
    checksum = hashlib.sha256(
        hashlib.sha256(version_payload).digest()
    ).digest()[:4]
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


def pub_point(priv_: int) -> tuple[int]:
    """
    Return (x, y) from priv_ key int on SECP256k1 curve
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
    checksum_check = hashlib.sha256(
        hashlib.sha256(decoded_addr[:-4]).digest()
    ).digest()
    assert checksum == checksum_check[:4]
    return decoded_addr[1:-4]  # remove version byte and checksum


def pubkey_xy_from_pubkey(pubkey_: bytes) -> tuple:
    # unfinished. unneeded?
    prefix = pubkey_[0]
    if prefix == b"\x02":
        # compressed
        # y is even
        pass
    elif prefix == b"\x03":
        # compressed
        # y is odd
        pass
    elif prefix == b"\x04":
        # uncompressed
        x = pubkey_[1:32].from_bytes(32, "big")
        y = pubkey_[33:].from_bytes(32, "big")
        return (x, y)
    else:
        raise ValueError("version byte misunderstood")
