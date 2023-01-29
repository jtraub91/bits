import secrets

from bits.ecmath import SECP256K1_N


def genkey() -> bytes:
    return secrets.randbelow(SECP256K1_N)
