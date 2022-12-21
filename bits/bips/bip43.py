"""
https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
BIP43

m/purpose'/*

Serialization
always use mainnet version magic from BIP32
"""
from typing import Tuple
from typing import Union

import bits.bips.bip32 as bip32


def serialized_extended_key(
    key: Union[int, Tuple[int]],
    chaincode: bytes,
    depth: bytes,
    parent_key_fingerprint: bytes,
    child_no: bytes,
) -> bytes:
    return bip32.serialized_extended_key(
        key,
        chaincode,
        depth,
        parent_key_fingerprint,
        child_no,
        testnet=False,  # testnet always False for BIP43
    )


def root_serialized_extended_key(
    master_key: Union[int, Tuple[int]],
    master_chain_code: bytes,
) -> bytes:
    return bip32.root_serialized_extended_key(
        master_key, master_chain_code, testnet=False
    )
