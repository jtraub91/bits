"""
https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
BIP43

m/purpose'/*

Serialization
always use mainnet version magic from BIP32
"""
from typing import Union

import bits.wallet.hd.bip32 as bip32


def serialized_extended_key(
    key: Union[int, tuple[int]],
    chaincode: bytes,
    depth: bytes,
    child_no: bytes,
    parent_key_fingerprint: bytes,
    public: bool = False,
) -> bytes:
    return bip32.serialized_extended_key(
        key,
        chaincode,
        depth,
        child_no,
        parent_key_fingerprint,
        testnet=False,  # testnet always False for BIP43
        public=public,
    )


def root_serialized_extended_key(
    master_key: Union[int, tuple[int]],
    master_chain_code: bytes,
    public: bool = False,
) -> bytes:
    return bip32.root_serialized_extended_key(
        master_key, master_chain_code, public=public, testnet=False
    )
