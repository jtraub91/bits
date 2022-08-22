import hashlib
import json
from typing import Union

from base58 import b58decode
from base58 import b58decode_check
from base58 import b58encode

import bits.bips.bip43 as bip43
from bits.bips.bip32 import CKDpriv
from bits.bips.bip32 import CKDpub
from bits.bips.bip32 import point
from bits.bips.bip32 import ser_p
from bits.bips.bip32 import to_master_key
from bits.bips.bip39 import generate_mnemonic_phrase
from bits.bips.bip39 import to_seed
from bits.utils import base58check
from bits.utils import pubkey_hash


HARDENED_OFFSET = 0x80000000


class DPath(dict):
    """
    Is this possible
    dpath["m/0/0/0"]

    hd_tree = { # BIP44 example
        44': {  # purpose
            0': {   # coin_type
                0': {   # account
                    0: {    #
                        0: {},
                        1: {},
                        2: {},
                        ...
                        n: {}
                    },
                    1: {    # change adresses
                        0: {},
                        1: {},
                        ...
                        m: {}
                    }
                }
            }
        }
    }
    dpath = {
        1: {
            0: (),
            1: (),
            2: ()

        },
        2: {

        },
        ...: {},
        max_depth: {

        }
    }

    """

    pass


def derive_child_key(xkey: str) -> str:
    """
    WIP
    Derives child xpub from parent xpub OR child xprv from parent xprv
    Args:
        xkey: str, parent xpub or xprv
    """
    decoded_ = b58decode_check(xkey)
    version = decoded_[:4]
    depth = decoded_[4:5]
    parent_key_fingerprint = decoded_[5:9]
    child_no = decoded_[9:13]
    chain_code = decoded_[13:45]
    key = decoded_[45:]
    # 78 bytes total

    return b58encode_check(version + depth + parent_key_fingerprint + child_no)

    if xkey.startswith("xpub"):
        pass
    elif xkey.startswith("xprv"):
        pass
    else:
        raise ValueError("extended key must start with xpub or xprv")
    return


def derive_from_path(
    path: str,
    master_extended_key: Union[
        tuple[int, bytes], tuple[tuple[int, int], bytes]
    ],
) -> Union[
    tuple[int, bytes, bytes, bytes, bytes],
    tuple[tuple[int], bytes, bytes, bytes, bytes],
]:
    """
    Derive extended key (pre-serialization) constants at particular path from a master extended key
    Args:
        path
        master_extended_key
    Returns:
        for private derivation,
        (key: int, chain_code: bytes, depth: bytes, parent_key_fingerprint: bytes, child_no: bytes)
        for public derivation,
        (Key: tuple[int], chain_code: bytes, depth: bytes, parent_key_fingerprint: bytes, child_no: bytes)
    """
    # path validation
    if path.startswith("m/"):
        ckd = CKDpriv
    elif path.startswith("M/"):
        raise NotImplementedError
        ckd = CKDpub
    else:
        raise ValueError("path must start with m/ or M/")
    tree_ = path.split("/")[1:]
    try:
        for t in tree_:
            if t.endswith("'"):
                val = t
                int(val[:-1])
            else:
                val = t
                int(val)
    except ValueError:
        raise ValueError(f"check path value: {val}")

    # parse tree values as list[int]
    path_tree = [
        int(t) if not t.endswith("'") else int(t[:-1]) + HARDENED_OFFSET
        for t in tree_
    ]
    # (child_no, key, depth)
    key_tree = [(0, master_extended_key[0], 0)]

    # derivation
    depth = 1
    child_no = path_tree[0]
    child = ckd(*master_extended_key, child_no)
    key_tree.append((child_no, child[0], depth))
    for depth, child_no in enumerate(path_tree[1:], start=2):
        child = ckd(*child, child_no)
        key_tree.append((child_no, child[0], depth))

    # calculate bytes data needed for serialization
    depth = depth.to_bytes(1, "big")
    parent_key_fingerprint = pubkey_hash(
        # SEC1 compressed parent's public key
        ser_p(point(key_tree[-2][1]))
        if path.startswith("m/")
        else ser_p(key_tree[-2][1])
    )[
        :4
    ]  # 1st 4 bytes for fingerprint
    child_no = child_no.to_bytes(4, "big")
    return *child, depth, parent_key_fingerprint, child_no


def p2pkh(xpub):
    """
    Return p2pkh bitcoin address from xpub
    """
    decoded_xpub_bytes = b58decode(xpub)
    checksum = decoded_xpub_bytes[-4:]
    checksum_check = hashlib.sha256(
        hashlib.sha256(decoded_xpub_bytes[:-4]).digest()
    ).digest()
    assert checksum == checksum_check[:4]
    payload = decoded_xpub_bytes[4:-4]  # remove 4 byte version and checksum

    pubkey_ = payload[-33:]  # last 33 bytes is pubkey in SEC1 compressed form

    version = b"\x00"
    pkh = pubkey_hash(pubkey_)
    return base58check(version, pkh).decode("ascii")


class HD:
    """
    BIP44, BIP43, BIP39, BIP32 compatible wallet
    """

    mnemonic: str = ""

    def __init__(
        self,
        passphrase: str = "",
        strength: int = 256,
        language: str = "english",
    ):
        if not self.mnemonic:
            self.mnemonic = generate_mnemonic_phrase(
                strength=strength, language=language
            )
        self.seed = to_seed(self.mnemonic, passphrase=passphrase)
        self.extended_master_key = to_master_key(self.seed)

    @classmethod
    def from_mnemonic(cls, mnemonic, passphrase: str = ""):
        cls.mnemonic = mnemonic
        return cls(passphrase=passphrase)

    def get_root_keys(self) -> tuple[str]:
        """
        Return tuple of serialized master (root) keys (xpub/xprv)
        base58(check) encoding
        Args:
            public: bool, True for xpub else xprv
        """
        xprv = bip43.root_serialized_extended_key(
            self.extended_master_key[0],
            self.extended_master_key[1],
        ).decode("ascii")
        xpub = bip43.root_serialized_extended_key(
            point(self.extended_master_key[0]),
            self.extended_master_key[1],
            public=True,
        ).decode("ascii")
        return xprv, xpub

    def get_xkeys_from_path(self, path: str) -> tuple[str]:
        """
        Derives child xkeys from path and class' master extended private key
        Args:
            path: str, path to extended key, e.g. m/44'/0'/0'/0/0
        Returns:
            xprv, xpub
        """
        (
            k_derived,
            c_derived,
            depth,
            parent_key_fingerprint,
            child_no,
        ) = derive_from_path(path, self.extended_master_key)
        print(
            k_derived,
            c_derived,
            depth,
            parent_key_fingerprint,
            child_no,
        )
        xprv = bip43.serialized_extended_key(
            k_derived,
            c_derived,
            depth,
            parent_key_fingerprint,
            child_no,
        )
        print(xprv)
        K_pub = point(k_derived)
        xpub = bip43.serialized_extended_key(
            K_pub,
            c_derived,
            depth,
            parent_key_fingerprint,
            child_no,
            public=True,
        )
        return xprv.decode("ascii"), xpub.decode("ascii")

    def get_address_from_path(self, path, type="p2pkh"):
        return

    def scan_for_utxo(self):
        """
        Scan blockchain for utxo owned by this wallet
        https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#address-gap-limit
        """
        return
