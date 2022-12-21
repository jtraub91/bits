"""
Wallet utils
"""
from typing import Tuple
from typing import Union

import bits.bips.bip32 as bip32
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
