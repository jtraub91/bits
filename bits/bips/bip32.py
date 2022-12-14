"""
BIP32
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
"""
import hashlib
import hmac
from typing import Tuple
from typing import Union

from bits.base58 import base58check
from bits.ecmath import add_mod_p
from bits.ecmath import SECP256K1_N
from bits.utils import pub_point
from bits.utils import pubkey

VERSION_PUBLIC_MAINNET = b"\x04\x88\xb2\x1e"
VERSION_PRIVATE_MAINNET = b"\x04\x88\xAD\xE4"
VERSION_PUBLIC_TESTNET = b"\x04\x35\x87\xCF"
VERSION_PRIVATE_TESTNET = b"\x04\x35\x83\x94"


# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#conventions
def point(p: int) -> tuple:
    """
    Returns the coordinate pair resulting from EC point multiplication
    of the secp256k1 base point with the integer p
    """
    return pub_point(p)


def ser_32(i: int) -> bytes:
    """
    Serialize i as 32 bits big endian
    """
    return i.to_bytes(4, "big")


def ser_256(p: int) -> bytes:
    """
    Serialize p as a 256 bits big-endian
    """
    return p.to_bytes(32, "big")


def ser_p(P: tuple) -> bytes:
    """
    Serialize P = (x, y) in SEC1 compressed form
    """
    x, y = P
    return pubkey(x, y, compressed=True)


def parse_256(p: bytes) -> int:
    """
    Parse 256 bit, big endian number, p, as integer
    """
    return int.from_bytes(p, "big")


### child key derivation (ckd) functions
##
def CKDpriv(k_parent: int, c_parent: bytes, i: int) -> Tuple[int, bytes]:
    """
    private parent to private child
    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
    e.g. CKDpriv
    CKDpriv(CKDpriv(CKDpriv(m, 3'), 2), 5) == m/3'/2/5
    """
    if i >= 2**31:
        # hardened child
        msg = b"\x00" + ser_256(k_parent) + ser_32(i)
        I = hmac.new(c_parent, msg, digestmod=hashlib.sha512).digest()
    else:
        # normal child
        msg = ser_p(point(k_parent)) + ser_32(i)
        I = hmac.new(c_parent, msg, digestmod=hashlib.sha512).digest()

    I_L = I[:32]
    I_R = I[32:]

    key_i = add_mod_p(parse_256(I_L), k_parent)
    chain_code_i = I_R

    assert parse_256(I_L) < SECP256K1_N
    assert key_i != 0

    return (key_i, chain_code_i)


def CKDpub(K_parent: Tuple[int], c_parent: bytes, i: int) -> Tuple[Tuple[int], bytes]:
    """
    public parent to public child
    """
    if i >= 2**31:
        raise ValueError(f"This function is not defined for hardened children")
    else:
        # normal child
        msg = ser_p(K_parent) + ser_32(i)
        I = hmac.new(c_parent, msg, digestmod=hashlib.sha512).digest()
    I_L = I[:32]
    I_R = I[32:]
    K_i = point(parse_256(I_L)) + K_parent  # + is point addition ! TODO implement
    c_i = I_R

    assert parse_256(I_L) < n
    # and assert K_i is not point at infinity
    return K_i, c_i


def N(k_parent, c_parent) -> Tuple[tuple, bytes]:
    """
    private parent to public child

    somewhat pointless function,
    would this mean that the xpub corresponding to a given xprv is its child
    in this context?
    """
    return point(k_parent), c_parent


def to_master_key(seed: bytes) -> Tuple[int, bytes]:
    """
    Defined in BIP32
    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation

    Args:
        seed: seed of chosen length (between 128 and 512 bits)
    """
    I = hmac.new(b"Bitcoin seed", seed, digestmod=hashlib.sha512).digest()
    master_secret_key = int.from_bytes(I[:32], "big")
    master_chain_code = I[32:]

    assert master_secret_key != 0

    # n for secp256k1, http://www.secg.org/sec2-v2.pdf
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    assert master_secret_key < n

    return (master_secret_key, master_chain_code)


def serialized_extended_key(
    key: Union[int, Tuple[int]],
    chaincode: bytes,
    depth: bytes,
    parent_key_fingerprint: bytes,
    child_no: bytes,
    testnet: bool = False,
    public: bool = False,
) -> bytes:
    """
    Return serialized base58 encoded extended key
    Args:
        key: private or public key
    """
    if public and not testnet:
        version = VERSION_PUBLIC_MAINNET
    elif not public and not testnet:
        version = VERSION_PRIVATE_MAINNET
    elif public and testnet:
        version = VERSION_PUBLIC_TESTNET
    elif not public and testnet:
        version = VERSION_PRIVATE_TESTNET

    payload = depth + parent_key_fingerprint + child_no + chaincode
    if public:
        payload += ser_p(key)  # or, pubkey(*key, compressed=True)
    else:
        payload += b"\x00" + ser_256(key)

    return base58check(version, payload)


def root_serialized_extended_key(
    master_key: Union[int, Tuple[int]],
    master_chain_code: bytes,
    public: bool = False,
    testnet: bool = False,
) -> bytes:
    return serialized_extended_key(
        master_key,
        master_chain_code,
        depth=b"\x00",
        parent_key_fingerprint=b"\x00\x00\x00\x00",
        child_no=b"\x00\x00\x00\x00",
        public=public,
        testnet=testnet,
    )
