from bits.btypes import Bytes

# https://github.com/bitcoin/bitcoin/blob/v23.0/src/script/script.h#L65-L206
SCRIPT_OPCODES = {
    # push value
    "OP_0": b"\x00",
    "OP_FALSE": b"\x00",    # OP_0
    # apparently 0x01 to 0x4b are interpreted as OP_PUSHBYTES_i,
    # https://bitcoin.stackexchange.com/a/84788/135678
    "OP_PUSHDATA1": b"\x4c",
    "OP_PUSHDATA2": b"\x4d",
    "OP_PUSHDATA4": b"\x4e",
    "OP_1NEGATE": b"\x4f",
    "OP_RESERVED": b"\x50",
    "OP_1": b"\x51",
    "OP_TRUE": b"\x51",     # OP_1
    "OP_2": b"\x52",
    "OP_3": b"\x53",
    "OP_4": b"\x54",
    "OP_5": b"\x55",
    "OP_6": b"\x56",
    "OP_7": b"\x57",
    "OP_8": b"\x58",
    "OP_9": b"\x59",
    "OP_10": b"\x5a",
    "OP_11": b"\x5b",
    "OP_12": b"\x5c",
    "OP_13": b"\x5d",
    "OP_14": b"\x5e",
    "OP_15": b"\x5f",
    "OP_16": b"\x60",

    # control
    "OP_NOP": b"\x61",
    "OP_VER": b"\x62",
    "OP_IF": b"\x63",
    "OP_NOTIF": b"\x64",
    "OP_VERIF": b"\x65",
    "OP_VERNOTIF": b"\x66",
    "OP_ELSE": b"\x67",
    "OP_ENDIF": b"\x68",
    "OP_VERIFY": b"\x69",
    "OP_RETURN": b"\x6a",

    # stack ops
    "OP_TOALTSTACK": b"\x6b",
    "OP_FROMALTSTACK": b"\x6c",
    "OP_2DROP": b"\x6d",
    "OP_2DUP": b"\x6e",
    "OP_3DUP": b"\x6f",
    "OP_2OVER": b"\x70",
    "OP_2ROT": b"\x71",
    "OP_2SWAP": b"\x72",
    "OP_IFDUP": b"\x73",
    "OP_DEPTH": b"\x74",
    "OP_DROP": b"\x75",
    "OP_DUP": b"\x76",
    "OP_NIP": b"\x77",
    "OP_OVER": b"\x78",
    "OP_PICK": b"\x79",
    "OP_ROLL": b"\x7a",
    "OP_ROT": b"\x7b",
    "OP_SWAP": b"\x7c",
    "OP_TUCK": b"\x7d",

    # splice ops
    "OP_CAT": b"\x7e",
    "OP_SUBSTR": b"\x7f",
    "OP_LEFT": b"\x80",
    "OP_RIGHT": b"\x81",
    "OP_SIZE": b"\x82",

    # bit logic
    "OP_INVERT": b"\x83",
    "OP_AND": b"\x84",
    "OP_OR": b"\x85",
    "OP_XOR": b"\x86",
    "OP_EQUAL": b"\x87",
    "OP_EQUALVERIFY": b"\x88",
    "OP_RESERVED1": b"\x89",
    "OP_RESERVED2": b"\x8a",

    # numeric
    "OP_1ADD": b"\x8b",
    "OP_1SUB": b"\x8c",
    "OP_2MUL": b"\x8d",
    "OP_2DIV": b"\x8e",
    "OP_NEGATE": b"\x8f",
    "OP_ABS": b"\x90",
    "OP_NOT": b"\x91",
    "OP_0NOTEQUAL": b"\x92",

    "OP_ADD": b"\x93",
    "OP_SUB": b"\x94",
    "OP_MUL": b"\x95",
    "OP_DIV": b"\x96",
    "OP_MOD": b"\x97",
    "OP_LSHIFT": b"\x98",
    "OP_RSHIFT": b"\x99",

    "OP_BOOLAND": b"\x9a",
    "OP_BOOLOR": b"\x9b",
    "OP_NUMEQUAL": b"\x9c",
    "OP_NUMEQUALVERIFY": b"\x9d",
    "OP_NUMNOTEQUAL": b"\x9e",
    "OP_LESSTHAN": b"\x9f",
    "OP_GREATERTHAN": b"\xa0",
    "OP_LESSTHANOREQUAL": b"\xa1",
    "OP_GREATERTHANOREQUAL": b"\xa2",
    "OP_MIN": b"\xa3",
    "OP_MAX": b"\xa4",

    "OP_WITHIN": b"\xa5",

    # crypto
    "OP_RIPEMD160": b"\xa6",
    "OP_SHA1": b"\xa7",
    "OP_SHA256": b"\xa8",
    "OP_HASH160": b"\xa9",
    "OP_HASH256": b"\xaa",
    "OP_CODESEPARATOR": b"\xab",
    "OP_CHECKSIG": b"\xac",
    "OP_CHECKSIGVERIFY": b"\xad",
    "OP_CHECKMULTISIG": b"\xae",
    "OP_CHECKMULTISIGVERIFY": b"\xaf",

    # expansion
    "OP_NOP1": b"\xb0",
    "OP_CHECKLOCKTIMEVERIFY": b"\xb1",
    "OP_NOP2": b"\xb1",     # OP_CHECKLOCKTIMEVERIFY
    "OP_CHECKSEQUENCEVERIFY": b"\xb2",
    "OP_NOP3": b"\xb2",     # OP_CHECKSEQUENCEVERIFY
    "OP_NOP4": b"\xb3",
    "OP_NOP5": b"\xb4",
    "OP_NOP6": b"\xb5",
    "OP_NOP7": b"\xb6",
    "OP_NOP8": b"\xb7",
    "OP_NOP9": b"\xb8",
    "OP_NOP10": b"\xb9",

    # Opcode added by BIP 342 (Tapscript)
    "OP_CHECKSIGADD": b"\xba",

    "OP_INVALIDOPCODE": b"\xff"
}

class Script(Bytes):

    def __init__(self, raw_bytes: bytes=b""):
        self._raw_bytes = raw_bytes

    def raw(self) -> bytes:
        return self._raw_bytes


class ScriptFactory:
    """
    Helper class to generate Script for standard tx types and provide other
    useful utilities
    
    TODO: provide Bitcoin VM evaluation of <scriptSig> <scriptPubKey>

    Docs:
        tx_types
            P2PKH
            tx_args->
                pubkeyhash: required
                sig: required
                pubkey: required

            P2SH -- Not Implemented
            tx_args

            ...
    """
    __STANDARD_TX = ["P2PKH", "P2PSH", "Pubkey", "Multisig", "Null Data"]

    def __init__(self, tx_type, **tx_args):
        super().__init__(self)
        if tx_args not in self.__STANDARD_TX:
            raise ValueError(f"Unrecognized transaction: {tx_type}")
        
        self.tx_type = tx_type
        if self.tx_type == "P2PKH":
            self._script_pubkey_asm_template = "OP_DUP OP_HASH160 <Public KeyHash> OP_EQUAL OP_CHECKSIG"
            self._script_sig_asm_template = "<Signature> <Public Key>"
        
        if not self.__validate_tx_args():
            raise ValueError("tx_args validation failed")
        self.tx_args = tx_args

    def __validate_tx_args(self):
        if self.tx_type == "P2PKH":
            tx_args["pubkeyhash"]
            tx_args["sig"]
            tx_args["pubkey"]
            return True
        return False

    def script_pubkey(self) -> Script:
         # f"OP_DUP OP_HASH160 {self.tx_args['pubkeyhash']} OP_EQUALVERIFY OP_CHECKSIG"
        if self.tx_type == "P2PKH":
            return Script(
                SCRIPT_OPCODES["OP_DUP"]
                + SCRIPT_OPCODES["OP_HASH160"]
                + len(pk_hash).to_bytes(1, "little")
                + pk_hash
                + SCRIPT_OPCODES["OP_EQUALVERIFY"]
                + SCRIPT_OPCODES["OP_CHECKSIG"]
            )
        else:
            raise NotImplementedError
    
    def script_sig(self) -> Script:
        if self.tx_type == "P2PKH":
            return Script(
                self.tx_args["sig"] + self.tx_args["pubkey"]
            )
        else:
            raise NotImplementedError

    def evaluate():
        raise NotImplementedError


def p2pkh_script_pubkey(pk_hash) -> Script:
    return Script(
            SCRIPT_OPCODES["OP_DUP"]
            + SCRIPT_OPCODES["OP_HASH160"]
            + len(pk_hash).to_bytes(1, "little")
            + pk_hash
            + SCRIPT_OPCODES["OP_EQUALVERIFY"]
            + SCRIPT_OPCODES["OP_CHECKSIG"]
        )
