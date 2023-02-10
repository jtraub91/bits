import secrets

from bits.ecmath import SECP256K1_N
from bits.utils import compute_point
from bits.utils import pubkey as pubkey_


def key() -> bytes:
    """
    Generate a private key
    """
    return secrets.randbelow(SECP256K1_N).to_bytes(32, "big")


def pub(privkey: bytes, compressed: bool = False) -> bytes:
    """
    Calculate public point and return pubkey
    Args:
        privkey: bytes, private key
    """
    x, y = compute_point(privkey)
    return pubkey_(x, y, compressed=compressed)
