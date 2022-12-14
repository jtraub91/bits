"""
BIP32, BIP39, BIP43, BIP44
"""
import hashlib
import json
from typing import Tuple
from typing import Union

from ecdsa import VerifyingKey
from ecdsa.curves import SECP256k1

import bits.bips.bip43 as bip43
from bits.base58 import base58check_decode
from bits.base58 import base58decode
from bits.bips.bip32 import CKDpriv
from bits.bips.bip32 import CKDpub
from bits.bips.bip32 import point as point_from_privkey
from bits.bips.bip32 import ser_p
from bits.bips.bip32 import to_master_key
from bits.bips.bip32 import VERSION_PRIVATE_MAINNET
from bits.bips.bip32 import VERSION_PRIVATE_TESTNET
from bits.bips.bip32 import VERSION_PUBLIC_MAINNET
from bits.bips.bip32 import VERSION_PUBLIC_TESTNET
from bits.bips.bip39 import generate_mnemonic_phrase
from bits.bips.bip39 import to_seed
from bits.utils import base58check
from bits.utils import point as point_from_pubkey
from bits.utils import pubkey_hash


HARDENED_OFFSET = 0x80000000


def xpub(xprv_):
    return


def derive_child(xkey: str, index: int) -> str:
    """
    Derives child xpub from parent xpub OR child xprv from parent xprv
    Args:
        xkey: str, parent xpub or xprv
        index: int, child number
    """
    if not xkey.startswith("xprv") and not xkey.startswith("xpub"):
        raise ValueError(f"must be xprv or xpub: {xkey}")

    decoded_ = base58check_decode(xkey)
    version = decoded_[:4]
    if version not in [
        VERSION_PRIVATE_MAINNET,
        # VERSION_PRIVATE_TESTNET,
        VERSION_PUBLIC_MAINNET,
        # VERSION_PUBLIC_TESTNET,
    ]:
        raise ValueError(f"Unrecognized version: {version}")

    # parent_key_fingerprint_parent = decoded_[5:9]
    # child_no_parent = decoded_[9:13]
    chain_code_parent = decoded_[13:45]
    key_parent = decoded_[45:]
    depth_parent = int.from_bytes(decoded_[4:5], "big")

    if key_parent.startswith(b"\x00"):
        if not xkey.startswith("xprv"):
            raise ValueError("decoded key is private, expected public")
        # private
        k_p = int.from_bytes(key_parent[1:], "big")
        key, chain_code = CKDpriv(k_p, chain_code_parent, index)
        key_data = b"\x00" + int.to_bytes(key, 32, "big")
        parent_key_fingerprint = pubkey_hash(ser_p(point_from_privkey(k_p)))[:4]
    elif key_parent.startswith(b"\x02") or key_parent.startswith(b"\x03"):
        if not xkey.startswith("xpub"):
            raise ValueError("decoded key is public, expected private")
        x, y = point_from_pubkey(key_parent)
        key, chain_code = CKDpub((x, y), chain_code_parent, index)
        key_data = ser_p(key)
        parent_key_fingerprint = pubkey_hash(key_parent)[:4]
    else:
        raise ValueError(f"key version byte: {key[0]}")

    depth = (depth_parent + 1).to_bytes(
        1, "big"
    )  # actually think this might be wrong, depth doesn't necessarily change...
    child_no = int.to_bytes(index, 4, "big")
    return base58check(
        version,
        depth + parent_key_fingerprint + child_no + chain_code + key_data,
    ).decode("ascii")


def derive_from_path(
    path: str,
    master_extended_key: Union[Tuple[int, bytes], Tuple[Tuple[int, int], bytes]],
) -> Union[
    Tuple[int, bytes, bytes, bytes, bytes],
    Tuple[Tuple[int], bytes, bytes, bytes, bytes],
]:
    """
    Derive extended key (pre-serialization) constants at particular path
    from a master extended key
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
        int(t) if not t.endswith("'") else int(t[:-1]) + HARDENED_OFFSET for t in tree_
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
    # fmt: off
    parent_key_fingerprint = pubkey_hash(
        # SEC1 compressed parent's public key
        ser_p(point_from_privkey(key_tree[-2][1]))
        if path.startswith("m/")
        else ser_p(key_tree[-2][1])
    )[:4]  # 1st 4 bytes for fingerprint
    # fmt: on
    child_no = child_no.to_bytes(4, "big")
    return child, depth, parent_key_fingerprint, child_no


def p2pkh(xpub):
    """
    Return p2pkh bitcoin address from xpub
    """
    decoded_xpub_bytes = base58check_decode(xpub)
    payload = decoded_xpub_bytes[4:]  # remove 4 byte version and checksum

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
        self.passphrase = passphrase
        if not self.mnemonic:
            self.mnemonic = generate_mnemonic_phrase(
                strength=strength, language=language
            )
        self.seed = to_seed(self.mnemonic, passphrase=self.passphrase)
        self.extended_master_key = to_master_key(self.seed)
        self.root_xprv, self.root_xpub = self.get_root_keys()

    @classmethod
    def from_mnemonic(cls, mnemonic, passphrase: str = ""):
        cls.mnemonic = mnemonic
        return cls(passphrase=passphrase)

    @classmethod
    def from_xkey(cls, xkey):
        raise NotImplementedError

    def get_root_keys(self) -> Tuple[str]:
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
            point_from_privkey(self.extended_master_key[0]),
            self.extended_master_key[1],
            public=True,
        ).decode("ascii")
        return xprv, xpub

    def get_xkeys_from_path(self, path: str) -> Tuple[str]:
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
        xprv = bip43.serialized_extended_key(
            k_derived,
            c_derived,
            depth,
            parent_key_fingerprint,
            child_no,
        )
        K_pub = point_from_privkey(k_derived)
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

    def print_tree(self, all: bool = False):
        """
        Return cached tree of se
        Args:
            all: bool, print keys and balances of all cached derivation paths
        """
        return
