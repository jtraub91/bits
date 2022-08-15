import hashlib
import hmac

from bits.btypes import pubkey
from bits.utils import pub_point

### conventions
## https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#conventions
def point(p: int) -> tuple:
    return pub_point(p)


def ser_32(i: int) -> bytes:
    return i.to_bytes(4, "big")


def ser_256(p: int) -> bytes:
    return p.to_bytes(32, "big")


def ser_p(P: tuple) -> bytes:
    x, y = P
    return pubkey(x, y, compressed=True)


def parse_256(p: bytes) -> int:
    return int.from_bytes(p, "big")


##
###
### extended keys
## https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#extended-keys


def extended_private_key(k: int, c: int):
    return


def extended_public_key(K, c):
    return


### child key derivation (ckd) functions
##


def private_parent_to_private_child(k_parent, c_parent, i) -> tuple:
    if i >= 2**31:
        # hardened child
        msg = b"\x00" + ser_256(k_parent) + ser_32(i)
        l = hmac.new(c_parent, msg, digestmod=hashlib.sha512)
    else:
        # normal child
        l = hmac.new(c_parent, digestmod=hashlib.sha512)
    return


def public_parent_to_public_child(K_parent: tuple, c_parent) -> tuple:
    return


def private_parent_to_public_child() -> tuple:
    return


def public_parent_to_private_child():
    raise NotImplementedError("This is not possible")


##
###

### The key Tree
##
##
###

### Key identifiers
## https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers
# ??
##
###

### Serialization format
##


def serialize(
    key: bytes,
    chain_code: bytes,
    depth: bytes = b"\x00",
    parent_key_fingerprint: bytes = None,
    child_number: bytes = None,
    master: bool = False,
    public: bool = False,
    network: str = "mainnet",
) -> bytes:
    if public and network == "mainnet":
        version = b"\x04\x88\xB2\x1E"
    elif not public and network == "mainnet":
        version = b"\x04\x88\xAD\xE4"
    elif public and network == "testnet":
        version = b"\x04\x35\x87\xCF"
    elif not public and network == "testnet":
        version = b"\x04\x35\x83\x94"
    else:
        raise ValueError(f"network not recognized: {network}")

    if master:
        parent_key_fingerint = b"\x00\x00\x00\x00"

    if master:
        child_number = b"\x00\x00\x00\x00"  # ser_32(i) for i in x_i = x_par / i ?? , 0x00000000 if master key

    return version + depth + parent_key_fingerint + child_number + chain_code + key


##
###

### Master key generation
## https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation


def to_master_key(S: bytes) -> tuple[bytes]:
    """
    Defined in BIP32
    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation

    Args:
        S: seed of chosen length (between 128 and 512 bits)
    """
    l = hmac.new(b"Bitcoin seed", S, digestmod=hashlib.sha512).digest()
    master_secret_key = l[:32]
    master_chain_code = l[32:]

    assert int.from_bytes(master_secret_key, "big") != 0

    # n for secp256k1, http://www.secg.org/sec2-v2.pdf
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    assert int.from_bytes(master_secret_key, "big") < n

    return (master_secret_key, master_chain_code)


##
###
