import secrets

import bits.ecmath


def key() -> bytes:
    """
    Generate a private key
    """
    return secrets.randbelow(bits.ecmath.SECP256K1_N).to_bytes(32, "big")


def pub(privkey: bytes, compressed: bool = False) -> bytes:
    """
    Calculate public point and return pubkey
    Args:
        privkey: bytes, private key
    """
    x, y = bits.compute_point(privkey)
    return bits.pubkey(x, y, compressed=compressed)
