"""
m / purpose' / coin_type' / account' / change / address_index
"""


import bits.wallet.hd.bip32 as bip32
from bits.wallet.hd.slip44 import coin_type

BIP44_PURPOSE_CONST = 0x8000002C  # 44'


def to_serialized_extended_key():
    return bip32.to_serialized_extended_key(
        key, chaincode, depth, child_no, parent_key_fingerprint
    )


def to_root_extended_key():
    return bip32.to_root_extended_key(
        master_key, master_chain_code, testnet=False
    )


def get_extended_keys_from_path(
    master: str,
    account: int,
    change: bool,
    address_index: int,
    coin: str = "BTC",
) -> str:
    """
    BIP44
    m / purpose' / coin_type' / account' / change / address_index
    """
    purpose = int.to_bytes(4, BIP44_PURPOSE_CONST, "big")
    cointype_ = coin_type(coin).to_bytes(4, "big")
