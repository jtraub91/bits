"""
Elliptic curve math
"""
import secrets
from typing import Tuple

# https://en.bitcoin.it/wiki/Secp256k1
# http://www.secg.org/sec2-v2.pdf - pg 13
# T(p, a, b, G, n, h)
# The curve E: y^2 = x^3 + ax + b over Fp,
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_A = 0x0000000000000000000000000000000000000000000000000000000000000000
SECP256K1_B = 0x0000000000000000000000000000000000000000000000000000000000000007
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP256K1_G_compressed = b"\x02\x79\xBE\x66\x7E\xF9\xDC\xBB\xAC\x55\xA0\x62\x95\xCE\x87\x0B\x07\x02\x9B\xFC\xDB\x2D\xCE\x28\xD9\x59\xF2\x81\x5B\x16\xF8\x17\x98"
SECP256K1_G_uncompressed = b"\x04\x79\xBE\x66\x7E\xF9\xDC\xBB\xAC\x55\xA0\x62\x95\xCE\x87\x0B\x07\x02\x9B\xFC\xDB\x2D\xCE\x28\xD9\x59\xF2\x81\x5B\x16\xF8\x17\x98\x48\x3A\xDA\x77\x26\xA3\xC4\x65\x5D\xA4\xFB\xFC\x0E\x11\x08\xA8\xFD\x17\xB4\x48\xA6\x85\x54\x19\x9C\x47\xD0\x8F\xFB\x10\xD4\xB8"
SECP256K1_G_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G_h = 0x01


def add_mod_p(
    x: int,
    y: int,
    p: int = SECP256K1_P,
) -> int:
    """
    x + y (mod p)

    >>> add_mod_p(SECP256K1_P - 1, 3)
    2
    """
    if x < 0 or x >= p:
        raise ValueError(f"{x} not in integer set of order {p}")
    if y < 0 or y >= p:
        raise ValueError(f"{y} not in integer set of order {p}")
    return (x + y) % p


def sub_mod_p(x: int, y: int, p: int = SECP256K1_P) -> int:
    """
    x - y (mod p)

    >>> hex(sub_mod_p(0, 1))
    '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e'
    """
    if x < 0 or x >= p:
        raise ValueError(f"{x} not in integer set of order {p}")
    if y < 0 or y >= p:
        raise ValueError(f"{y} not in integer set of order {p}")
    return (x - y) % p


def mul_mod_p(x: int, y: int, p: int = SECP256K1_P) -> int:
    """
    x * y (mod p)
    """
    if x < 0 or x >= p:
        raise ValueError(f"{x} not in integer set of order {p}")
    if y < 0 or y >= p:
        raise ValueError(f"{y} not in integer set of order {p}")
    return (x * y) % p


def pow_mod_p(x: int, y: int, p: int = SECP256K1_P) -> int:
    """
    x ** y (mod p)
    """
    if x < 0 or x >= p:
        raise ValueError(f"{x} not in integer set of order {p}")
    if not type(y) is int:
        raise TypeError(f"{y} must be an integer")
        # y need not be in field p
    return pow(x, y, p)  # more efficient than (x ** y) % p ¯\_(ツ)_/¯


def div_mod_p(x: int, y: int, p: int = SECP256K1_P) -> int:
    """
    x / y (mod p)
    Using Fermat's little thereom,
    mod p
    x / y = x * (y ** -1)
    x / y = x * (y ** (p - 2))
    """
    if x < 0 or x >= p:
        raise ValueError(f"{x} not in integer set of order {p}")
    if y < 0 or y >= p:
        raise ValueError(f"{y} not in integer set of order {p}")
    return mul_mod_p(x, pow_mod_p(y, p - 2, p), p)


def sqrt_mod_p(x: int, p: int = SECP256K1_P) -> int:
    # TODO: tonelli shank's algorithm, works for all prime p
    # https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
    # https://www.geeksforgeeks.org/find-square-root-modulo-p-set-2-shanks-tonelli-algorithm/
    # TODO: check euler criterion
    # https://en.wikipedia.org/wiki/Euler's_criterion
    # x ** (p-1)/2 == 1 or -1 (1 if sqrt exists)

    x = add_mod_p(0, x)
    # https://www.geeksforgeeks.org/find-square-root-under-modulo-p-set-1-when-p-is-in-form-of-4i-3/
    if p % 4 == 3:
        # +/-
        y = pow_mod_p(x, (p + 1) // 4, p=p)
        return y, sub_mod_p(0, y, p=p)
    else:
        raise NotImplementedError


def y_from_x(x: int, a: int = SECP256K1_A, b: int = SECP256K1_B) -> int:
    """
    Find y from x
    y^2 = x^3 + ax + b
    """
    y_squared = add_mod_p(add_mod_p(pow_mod_p(x, 3), mul_mod_p(a, x)), b)
    return sqrt_mod_p(y_squared)


def point_is_on_curve(
    x: int, y: int, a: int = SECP256K1_A, b: int = SECP256K1_B
) -> bool:
    """
    Returns True if (x, y) is on elliptic curve given by y^2 = x^3 + ax + b, else False
    >>> point_is_on_curve(SECP256K1_Gx, SECP256K1_Gy)
    True
    """
    if pow_mod_p(y, 2) == add_mod_p(add_mod_p(pow_mod_p(x, 3), mul_mod_p(x, a)), b):
        return True
    return False


def point_negate(
    p: Tuple[int, int], a: int = SECP256K1_A, b: int = SECP256K1_B
) -> Tuple[int, int]:
    """
    Returns:
        -p
    """
    # https://crypto.stanford.edu/pbc/notes/elliptic/explicit.html
    x, y = p
    return (x, sub_mod_p(0, y))


def point_add(
    p1: Tuple[int, int], p2: Tuple[int, int], a: int = SECP256K1_A, b: int = SECP256K1_B
) -> Tuple[int, int]:
    # https://crypto.stanford.edu/pbc/notes/elliptic/explicit.html
    # y^2 + a1*x*y + a3*y = x^3 + a2 * x^2 + a4*x + a6
    # a1 = a2 = a3 = 0
    # a4 = a
    # a6 = b
    # y^2 = x^3 + ax + b
    if p1 is None:
        return p2
    elif p2 is None:
        return p1
    elif p1 == p2:
        x, y = p1
        # s = (3 * x ** 2 + a) / (2 * y)
        # xr = s ** 2 - 2 * x
        # yr = - s * xr + s * x - y
        s = div_mod_p(add_mod_p(mul_mod_p(3, pow_mod_p(x, 2)), a), mul_mod_p(2, y))
        xr = sub_mod_p(pow_mod_p(s, 2), mul_mod_p(2, x))
        yr = sub_mod_p(add_mod_p(mul_mod_p(sub_mod_p(0, s), xr), mul_mod_p(s, x)), y)
        return (xr, yr)
    elif p1 == point_negate(p2):
        return None
    else:
        x1, y1 = p1
        x2, y2 = p2
        # s = y2 - y1 / x2 - x1
        s = div_mod_p(sub_mod_p(y2, y1), sub_mod_p(x2, x1))
        # xr = s ** 2 - x1 - x2
        xr = sub_mod_p(sub_mod_p(pow_mod_p(s, 2), x1), x2)
        # yr = - s * xr + s * x1 - y1
        yr = sub_mod_p(add_mod_p(mul_mod_p(sub_mod_p(0, s), xr), mul_mod_p(s, x1)), y1)
        return (xr, yr)


def point_scalar_mul(
    k: int, P: Tuple[int, int], a: int = SECP256K1_A, b: int = SECP256K1_B
) -> Tuple[int, int]:
    """
    Point multiplication using double and add algorithm
    kP where k has n binary digits
    O(k)
    """
    # https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
    # https://en.wikipedia.org//wiki/Elliptic_curve_point_multiplication
    # https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
    result = None
    bit_depth = k.bit_length()
    for bit_no in reversed(range(bit_depth)):
        result = point_add(result, result)  # double
        if k & (2**bit_no):
            result = point_add(result, P)  # add
    return result


def sign(
    key: int,
    digest: int,
    N: int = SECP256K1_N,
    G: Tuple[int, int] = (SECP256K1_Gx, SECP256K1_Gy),
) -> Tuple[int, int]:
    # https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    r = 0
    s = 0
    while not r or not s:
        k = secrets.randbelow(N)
        while not k:
            k = secrets.randbelow(N)
        x, y = point_scalar_mul(k, G)
        r = x % N
        if r:
            s = div_mod_p(add_mod_p(digest % N, mul_mod_p(r, key, p=N), p=N), k, p=N)
            if s > SECP256K1_N // 2 or s < 1:
                # s = N - s
                s = sub_mod_p(0, s, p=N)
    return (r, s)


def verify(
    r: int,
    s: int,
    point: Tuple[int, int],
    digest: int,
    N: int = SECP256K1_N,
    G: Tuple[int, int] = (SECP256K1_Gx, SECP256K1_Gy),
) -> bool:
    assert r in range(1, N), "r out of range [1, N)"
    assert s in range(1, N), "s out of range [1, N)"
    u1 = div_mod_p(digest, s, p=N)
    u2 = div_mod_p(r, s, p=N)
    x, y = point_add(point_scalar_mul(u1, G), point_scalar_mul(u2, point))
    assert point_is_on_curve(x, y), "point is not on curve"
    assert r == x % N, "invalid signature"
    return True
