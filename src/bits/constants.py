"""
Global constants
"""

WITNESS_RESERVED_VALUE = b"\x00" * 32

# https://github.com/bitcoin/bitcoin/blob/v0.2.13/main.h#L17
# https://github.com/bitcoin/bitcoin/blob/v23.0/src/serialize.h#L31
MAX_SIZE = 0x02000000
COIN = 100000000  # satoshis / bitcoin
CENT = 1000000
COINBASE_MATURITY = 100

NULL_32 = b"\x00" * 32
# https://github.com/bitcoin/bitcoin/blob/v23.0/src/node/blockstorage.h#L43
MAX_BLOCKFILE_SIZE = 0x8000000  # 128 MiB


# https://developer.bitcoin.org/reference/block_chain.html#target-nbits
MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
MAX_TARGET_REGTEST = 0x7FFFFF0000000000000000000000000000000000000000000000000000000000


UINT32_MAX = 2**32 - 1

# https://github.com/bitcoin/bitcoin/blob/v0.4.0/src/main.h#L40-L41
# "Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp."
LOCKTIME_THRESHOLD = 500000000  # Tue Nov  5 00:53:20 1985 UTC

# Magic start strings
# https://github.com/bitcoin/bitcoin/blob/v23.0/src/chainparams.cpp#L102-L105
MAINNET_START = b"\xF9\xBE\xB4\xD9"
TESTNET_START = b"\x0B\x11\x09\x07"
REGTEST_START = b"\xFA\xBF\xB5\xDA"
