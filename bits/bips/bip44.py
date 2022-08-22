"""
BIP44
m / purpose' / coin_type' / account' / change / address_index
"""
import bits.bips.bip32 as bip32
from bits.bips.slip44 import coin_type

BIP44_PURPOSE_CONST = 0x8000002C  # 44'
