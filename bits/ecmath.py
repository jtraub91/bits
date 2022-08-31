"""
Notes and (re/para)phrasing from Programming Bitcoin, Jimmy Song
https://github.com/jimmysong/programmingbitcoin

Ch1

https://en.wikipedia.org/wiki/Set_(mathematics)
https://en.wikipedia.org/wiki/Group_(mathematics)
https://en.wikipedia.org/wiki/Field_(mathematics)
https://en.wikipedia.org/wiki/Finite_field
https://en.wikipedia.org/wiki/Modular_arithmetic
https://en.wikipedia.org/wiki/Fermat's_little_theorem

Finite Fields (Galois field) are have the following properties

1. Closed: if a and b are in the set, a+b and a*b are in the set
2. Additive Identity: 0 exists and has the property a + 0 = a
3. Multiplicative Identity: 1 exists and has the propert a * 1 = a
4. Additive Inverse: If a is in the set, -a is in the set, defined as the value in which
    a + (-a) = 0 
5. Multiplicative Inverse: If a is in the set (and is not 0), a^-1 is in the set
    and is defined as the value in which a * (a^-1) = 1


Let `p` be the order of the Finite Field set (how big the set is)

F_p = set([0, 1, 2, ..., p-1])

??finite field elements in general need not be integers, and p is, strictly speaking, the number of elements

"it turns out that fields must have an order that is a power of a prime, and that the finite fields whose order is prime are the ones we’re interested in"
JT: The set of integers, with order p, where p is prime, turns out to be a (finite) field
    by using modular arithmetic


Fermat's little thereom essentially states

(n**(p-1))%p = 1 where p is prime (and n > 0 ?)

Ch2
...

Ch3
...
"""
"""
Elliptic curve math
"""
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
    """
    if x < 0 or x >= p:
        raise ValueError(f"{x} not in integer set of order {p}")
    if y < 0 or y >= p:
        raise ValueError(f"{y} not in integer set of order {p}")
    return (x + y) % p


def sub_mod_p(x: int, y: int, p: int = SECP256K1_P) -> int:
    """
    x - y (mod p)
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
    # why does jimmy song use (exp) % (p-1) before pow function?
    # because prior to python 3.8 pow(n, exp) did not support negative exp


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


# ch2 / 3
# Elliptic curve cryptography
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
