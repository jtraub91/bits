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


#### Script constants

### Signature hash types/flags
## https://github.com/bitcoin/bitcoin/blob/v23.0/src/script/interpreter.h#L28-L35

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

SIGHASH_DEFAULT = 0  # !< Taproot only; implied when sighash byte is missing, and equivalent to SIGHASH_ALL
SIGHASH_OUTPUT_MASK = 3
SIGHASH_INPUT_MASK = 0x80


### Script opcodes
## https://github.com/bitcoin/bitcoin/blob/v23.0/src/script/script.h#L65-L206

# push value
OP_0 = 0x00
OP_FALSE = OP_0
# apparently 0x01 to 0x4b are interpreted as OP_PUSHBYTES_i,
# https://bitcoin.stackexchange.com/a/84788/135678
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1NEGATE = 0x4F
OP_RESERVED = 0x50
OP_1 = 0x51
OP_TRUE = OP_1
OP_2 = 0x52
OP_3 = 0x53
OP_4 = 0x54
OP_5 = 0x55
OP_6 = 0x56
OP_7 = 0x57
OP_8 = 0x58
OP_9 = 0x59
OP_10 = 0x5A
OP_11 = 0x5B
OP_12 = 0x5C
OP_13 = 0x5D
OP_14 = 0x5E
OP_15 = 0x5F
OP_16 = 0x60

# control
OP_NOP = 0x61
OP_VER = 0x62
OP_IF = 0x63
OP_NOTIF = 0x64
OP_VERIF = 0x65
OP_VERNOTIF = 0x66
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_RETURN = 0x6A

# stack ops
OP_TOALTSTACK = 0x6B
OP_FROMALTSTACK = 0x6C
OP_2DROP = 0x6D
OP_2DUP = 0x6E
OP_3DUP = 0x6F
OP_2OVER = 0x70
OP_2ROT = 0x71
OP_2SWAP = 0x72
OP_IFDUP = 0x73
OP_DEPTH = 0x74
OP_DROP = 0x75
OP_DUP = 0x76
OP_NIP = 0x77
OP_OVER = 0x78
OP_PICK = 0x79
OP_ROLL = 0x7A
OP_ROT = 0x7B
OP_SWAP = 0x7C
OP_TUCK = 0x7D

# splice ops
OP_CAT = 0x7E
OP_SUBSTR = 0x7F
OP_LEFT = 0x80
OP_RIGHT = 0x81
OP_SIZE = 0x82

# bit logic
OP_INVERT = 0x83
OP_AND = 0x84
OP_OR = 0x85
OP_XOR = 0x86
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_RESERVED1 = 0x89
OP_RESERVED2 = 0x8A

# numeric
OP_1ADD = 0x8B
OP_1SUB = 0x8C
OP_2MUL = 0x8D
OP_2DIV = 0x8E
OP_NEGATE = 0x8F
OP_ABS = 0x90
OP_NOT = 0x91
OP_0NOTEQUAL = 0x92

OP_ADD = 0x93
OP_SUB = 0x94
OP_MUL = 0x95
OP_DIV = 0x96
OP_MOD = 0x97
OP_LSHIFT = 0x98
OP_RSHIFT = 0x99

OP_BOOLAND = 0x9A
OP_BOOLOR = 0x9B
OP_NUMEQUAL = 0x9C
OP_NUMEQUALVERIFY = 0x9D
OP_NUMNOTEQUAL = 0x9E
OP_LESSTHAN = 0x9F
OP_GREATERTHAN = 0xA0
OP_LESSTHANOREQUAL = 0xA1
OP_GREATERTHANOREQUAL = 0xA2
OP_MIN = 0xA3
OP_MAX = 0xA4

OP_WITHIN = 0xA5

# crypto
OP_RIPEMD160 = 0xA6
OP_SHA1 = 0xA7
OP_SHA256 = 0xA8
OP_HASH160 = 0xA9
OP_HASH256 = 0xAA
OP_CODESEPARATOR = 0xAB
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF

# expansion
OP_NOP1 = 0xB0
OP_CHECKLOCKTIMEVERIFY = 0xB1
OP_NOP2 = OP_CHECKLOCKTIMEVERIFY
OP_CHECKSEQUENCEVERIFY = 0xB2
OP_NOP3 = OP_CHECKSEQUENCEVERIFY
OP_NOP4 = 0xB3
OP_NOP5 = 0xB4
OP_NOP6 = 0xB5
OP_NOP7 = 0xB6
OP_NOP8 = 0xB7
OP_NOP9 = 0xB8
OP_NOP10 = 0xB9

# Opcode added by BIP 342 (Tapscript)
OP_CHECKSIGADD = 0xBA

OP_INVALIDOPCODE = 0xFF
