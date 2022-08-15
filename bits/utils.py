import hashlib

from base58 import b58decode
from ecdsa import SigningKey, SECP256k1


def pub_point(priv_: int) -> tuple:
    sk = SigningKey.from_secret_exponent(priv_, curve=SECP256k1)
    return sk.verifying_key.pubkey.point.x(), sk.verifying_key.pubkey.point.y()


def d_hash(msg: bytes) -> bytes:
    """
    Double sha256 hash of msg
    """
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def pubkey_hash_from_bitcoin_address(baddr: bytes) -> bytes:
    """
    Return pubkeyhash from bitcoin address, with checksum verification
    """
    decoded_addr = b58decode(baddr)
    checksum = decoded_addr[-4:]
    checksum_check = hashlib.sha256(hashlib.sha256(decoded_addr[:-4]).digest()).digest()
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
