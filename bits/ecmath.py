"""
Elliptic curve math
"""
# n for secp256k1, http://www.secg.org/sec2-v2.pdf
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def add_mod_n(
    x: int,
    y: int,
    n: int = n,
):
    # n for secp256k1, http://www.secg.org/sec2-v2.pdf
    raise NotImplementedError
    z = x + y
    if z < n:
        return z
    elif z >= n:
        return z - n
    else:
        return
