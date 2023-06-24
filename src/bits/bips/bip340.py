"""
Schnorr sigs (on secp256k1)
https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
"""
import hashlib
import secrets
from typing import Optional
from typing import Tuple

from bits.crypto import sha256
from bits.ecmath import add_mod_p
from bits.ecmath import point_add
from bits.ecmath import point_is_on_curve
from bits.ecmath import point_negate
from bits.ecmath import point_scalar_mul
from bits.ecmath import pow_mod_p
from bits.ecmath import SECP256K1_Gx
from bits.ecmath import SECP256K1_Gy
from bits.ecmath import SECP256K1_N
from bits.ecmath import SECP256K1_P
from bits.ecmath import sub_mod_p


def pubkey(point: Tuple[int, int]) -> bytes:
    """
    Returns a BIP0340 pubkey from point
    """
    x, y = point
    assert point_is_on_curve(x, y), "point is not on the curve"
    return x.to_bytes(32, "big")


def lift_x(x: bytes) -> Tuple[int, int]:
    """
    Helper function as defined in BIP340
    Returns:
        (x, y) coordinates from x-coordinate pubkey
    """
    assert int.from_bytes(x, "big") < SECP256K1_P, "x is >= P"
    c = add_mod_p(pow_mod_p(int.from_bytes(x, "big"), 3), 7)
    y = pow_mod_p(c, (SECP256K1_P + 1) // 4)
    assert c == pow_mod_p(y, 2), "c must be equal to y squared mod p"
    return (
        (int.from_bytes(x, "big"), y)
        if y % 2 == 0
        else (int.from_bytes(x, "big"), SECP256K1_P - y)
    )


def sign(key: bytes, digest: bytes, aux: Optional[bytes] = None) -> bytes:
    """
    Schnorr sigs (on secp256k1) per
    https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing
    """
    if not aux:
        aux = secrets.randbits(32)
    key = int.from_bytes(key, "big")
    if key == 0 or key >= SECP256K1_N:
        raise ValueError("invalid secret key")
    Px, Py = point_scalar_mul(key, (SECP256K1_Gx, SECP256K1_Gy))

    d = key if not Py % 2 else SECP256K1_N - key

    tag = "BIP0340/aux".encode("utf8")
    t = (key ^ int.from_bytes(sha256(sha256(tag) + sha256(tag) + aux), "big")).to_bytes(
        32, "big"
    )

    tag = "BIP0340/nonce".encode("utf8")
    rand = sha256(sha256(tag) + sha256(tag) + t + Px.to_bytes(32, "big") + digest)
    k_prime = int.from_bytes(rand, "big") % SECP256K1_N
    assert k_prime != 0, "k_prime cannot be zero"
    Rx, Ry = point_scalar_mul(k_prime, (SECP256K1_Gx, SECP256K1_Gy))
    k = k_prime if not Ry % 2 else SECP256K1_N - k_prime

    tag = "BIP0340/challenge".encode("utf8")
    e = (
        int.from_bytes(
            sha256(
                sha256(tag)
                + sha256(tag)
                + Rx.to_bytes(32, "big")
                + Px.to_bytes(32, "big")
                + digest
            ),
            "big",
        )
        % SECP256K1_N
    )
    sig = Rx.to_bytes(32, "big") + ((k + e * d) % SECP256K1_N).to_bytes(32, "big")
    assert verify(Px.to_bytes(32, "big"), digest, sig)
    return sig


def verify(pk: bytes, m: bytes, sig: bytes) -> bool:
    """
    Schnorr sig verification per
    https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification
    """
    x, y = lift_x(pk)
    r = int.from_bytes(sig[:32], "big")
    assert r < SECP256K1_P, "r >= p"
    s = int.from_bytes(sig[32:], "big")
    assert s < SECP256K1_N, "s >= n"
    tag = "BIP0340/challenge".encode("utf8")
    e = (
        int.from_bytes(
            sha256(
                sha256(tag)
                + sha256(tag)
                + r.to_bytes(32, "big")
                + x.to_bytes(32, "big")
                + m
            ),
            "big",
        )
        % SECP256K1_N
    )
    R = point_add(
        point_scalar_mul(s, (SECP256K1_Gx, SECP256K1_Gy)),
        point_negate(point_scalar_mul(e, (x, y))),
    )
    assert R is not None, "R is point at infinity"
    assert R[1] % 2 == 0, "Ry is odd"
    assert R[0] == r, "Rx != r"
    return "OK"
