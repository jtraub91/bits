"""
BIP32, BIP39, BIP43, BIP44
"""
import hashlib
import json
import secrets
from typing import Tuple
from typing import Union

import bits.bips.bip32 as bip32
import bits.bips.bip39 as bip39
import bits.bips.bip43 as bip43
from bits.base58 import base58check
from bits.base58 import base58check_decode
from bits.base58 import base58decode
from bits.utils import point
from bits.utils import pubkey_hash


def get_xpub(xprv_: bytes):
    """
    Return xpub from xprv
    Args:
        xprv_: bytes, serialized extended private key
    """
    (
        version,
        depth,
        parent_key_fingerprint,
        child_no,
        chaincode,
        key,
    ) = bip32.deserialized_extended_key(xprv_)
    K = bip32.point(key)
    return bip32.serialized_extended_key(
        K, chaincode, depth, parent_key_fingerprint, child_no
    )


def derive_from_path(
    path: str,
    master_extended_key: bytes,
) -> bytes:
    """
    Derive extended key at particular path from master extended key
    Args:
        path: str, path in shortened notation, e.g. m/0'/1
        master_extended_key: bytes, serialized master extended key
    """
    (
        version,
        depth,
        parent_key_fingerprint,
        child_no,
        chaincode,
        master_key,
    ) = bip32.deserialized_extended_key(master_extended_key)
    testnet = version in [bip32.VERSION_PRIVATE_TESTNET, bip32.VERSION_PUBLIC_TESTNET]
    public = version in [bip32.VERSION_PUBLIC_MAINNET, bip32.VERSION_PUBLIC_TESTNET]
    if path == "m":
        if version not in [
            bip32.VERSION_PRIVATE_MAINNET,
            bip32.VERSION_PRIVATE_TESTNET,
        ]:
            raise ValueError("version mismatch")
        return master_extended_key
    elif path == "M":
        if version not in [bip32.VERSION_PUBLIC_MAINNET, bip32.VERSION_PUBLIC_TESTNET]:
            raise ValueError("version mismatch")
        return master_extended_key
    elif path.startswith("m/"):
        ckd = bip32.CKDpriv
    elif path.startswith("M/"):
        raise NotImplementedError
        ckd = bip32.CKDpub
    else:
        raise ValueError("path must start with m or M")
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
        int(t) if not t.endswith("'") else int(t[:-1]) + bip32.HARDENED_OFFSET
        for t in tree_
    ]
    key_tree = [master_extended_key]

    for depth, child_no in enumerate(path_tree, start=1):
        parent = key_tree[depth - 1]
        _, _, _, _, parent_chaincode, parent_key = bip32.deserialized_extended_key(
            parent
        )
        child = ckd(parent_key, parent_chaincode, child_no)
        if public:
            parent_key_fingerprint = pubkey_hash(bip32.ser_p(parent_key))[:4]
        else:
            parent_key_fingerprint = pubkey_hash(bip32.ser_p(bip32.point(parent_key)))[
                :4
            ]
        child_ser = bip32.serialized_extended_key(
            child[0],
            child[1],
            depth.to_bytes(1, "big"),
            parent_key_fingerprint,
            child_no.to_bytes(4, "big"),
            testnet=testnet,
        )
        key_tree.append(child_ser)
    return key_tree[-1]


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
        bip32.VERSION_PRIVATE_MAINNET,
        # bip32.VERSION_PRIVATE_TESTNET,
        bip32.VERSION_PUBLIC_MAINNET,
        # bip32.VERSION_PUBLIC_TESTNET,
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
        key, chain_code = bip32.CKDpriv(k_p, chain_code_parent, index)
        key_data = b"\x00" + int.to_bytes(key, 32, "big")
        parent_key_fingerprint = pubkey_hash(bip32.ser_p(bip32.point(k_p)))[:4]
    elif key_parent.startswith(b"\x02") or key_parent.startswith(b"\x03"):
        if not xkey.startswith("xpub"):
            raise ValueError("decoded key is public, expected private")
        x, y = point(key_parent)
        key, chain_code = bip32.CKDpub((x, y), chain_code_parent, index)
        key_data = bip32.ser_p(key)
        parent_key_fingerprint = pubkey_hash(key_parent)[:4]
    else:
        raise ValueError(f"key version byte: {key[0]}")

    depth = (depth_parent + 1).to_bytes(
        1, "big"
    )  # actually think this might be wrong, depth doesn't necessarily change...
    child_no = int.to_bytes(index, 4, "big")
    return base58check(
        version + depth + parent_key_fingerprint + child_no + chain_code + key_data,
    ).decode("ascii")


def p2pkh(xpub):
    """
    Return p2pkh bitcoin address from xpub
    """
    decoded_xpub_bytes = base58check_decode(xpub)
    payload = decoded_xpub_bytes[4:]  # remove 4 byte version and checksum

    pubkey_ = payload[-33:]  # last 33 bytes is pubkey in SEC1 compressed form

    version = b"\x00"
    pkh = pubkey_hash(pubkey_)
    return base58check(version + pkh).decode("ascii")


class HD:
    """
    BIP44, BIP43, BIP39, BIP32 compatible wallet
    """

    ADDR_GAP_LIMIT: int = 20

    mnemonic: str = ""

    def __init__(
        self,
        passphrase: str = "",
        strength: int = 256,
    ):
        self.passphrase = passphrase
        if not self.mnemonic:
            entropy = secrets.token_bytes(strength // 8)
            self.mnemonic = bip39.calculate_mnemonic_phrase(entropy)
        self.strength = len(self.mnemonic) * 8
        self.seed = bip39.to_seed(self.mnemonic, passphrase=self.passphrase)
        self.extended_master_key = bip32.to_master_key(self.seed)
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
            bip32.point(self.extended_master_key[0]),
            self.extended_master_key[1],
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
        K_pub = bip32.point(k_derived)
        xpub = bip43.serialized_extended_key(
            K_pub,
            c_derived,
            depth,
            parent_key_fingerprint,
            child_no,
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
