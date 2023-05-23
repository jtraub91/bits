import logging
import typing

import bits.base58
from bits.bips import bip173
from bits.script import constants

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def scriptpubkey(data: bytes) -> bytes:
    """
    Create scriptpubkey by inferring input data type.
    Returns identity if data not identified as pubkey, base58check, nor segwit

    >>> # p2pk
    >>> scriptpubkey(bytes.fromhex("025a058ec9fb35845ce07b6ec4929b443132b2fce2bb154e3aa66c19b851b0c449")).hex()
    '21025a058ec9fb35845ce07b6ec4929b443132b2fce2bb154e3aa66c19b851b0c449ac'
    >>> # p2pkh
    >>> scriptpubkey(b"1A4wionHnAtthCbCb9CTmDJaKuEPNXZp8R").hex()
    '76a91463780efe21b54d462d399b4c5b9902235aa570ec88ac'
    >>> # p2sh
    >>> scriptpubkey(b"3PSFZTX6WxhFTmPBLnCh6gwxomb4vvxSpP").hex()
    'a914ee87e9344a5ef0f83a0aa250256a3cc394ab750387'
    >>> # p2wpkh
    >>> scriptpubkey(b"bc1qvduqal3pk4x5vtfendx9hxgzydd22u8v0pzd7h").hex()
    '001463780efe21b54d462d399b4c5b9902235aa570ec'
    >>> # TODO: p2wsh
    >>> # raw
    >>> scriptpubkey(bytes.fromhex("5221024c9b21035e4823d6f09d5a948201d14086d854dfa5bba828c06f5131d9cfe14f2103fe0b5ca0ab60705b21a00cbd9900026f282c7188427123e87e0dc344ce742eb02102528e776c2bf0be68f4503151fd036c9cb720c4977f6f5b0248d5472c654aebe453ae")).hex()
    '5221024c9b21035e4823d6f09d5a948201d14086d854dfa5bba828c06f5131d9cfe14f2103fe0b5ca0ab60705b21a00cbd9900026f282c7188427123e87e0dc344ce742eb02102528e776c2bf0be68f4503151fd036c9cb720c4977f6f5b0248d5472c654aebe453ae'
    """
    # data is either pubkey, base58check, or segwit
    if bits.is_point(data):
        return p2pk_script_pubkey(data)
    elif bits.base58.is_base58check(data):
        decoded = bits.base58.base58check_decode(data)
        version, payload = decoded[0:1], decoded[1:]
        if version in [b"\x00", b"\x6f"]:
            # addr_type = "p2pkh"
            script_pubkey = p2pkh_script_pubkey(payload)
        elif version in [b"\x05", b"\xc4"]:
            # addr_type = "p2sh"
            script_pubkey = p2sh_script_pubkey(payload)
        else:
            raise ValueError(f"unrecognized base58check version byte: {version}")
        return script_pubkey
    elif bip173.is_segwit_addr(data):
        # segwit
        hrp, witness_version, witness_program = bip173.decode_segwit_addr(data)
        assert hrp in [b"bc", b"tb", b"bcrt"], "unrecognized hrp"
        if len(witness_program) == 20:
            return p2wpkh_script_pubkey(
                witness_program, witness_version=witness_version
            )
        elif len(witness_program) == 32:
            return p2wsh_script_pubkey(witness_program, witness_version=witness_version)
        else:
            raise ValueError("bad witness program length")
    else:
        return data


def p2pkh_script_pubkey(pk_hash: bytes) -> bytes:
    return (
        constants.OP_DUP.to_bytes(1, "little")
        + constants.OP_HASH160.to_bytes(1, "little")
        + len(pk_hash).to_bytes(1, "little")
        + pk_hash
        + constants.OP_EQUALVERIFY.to_bytes(1, "little")
        + constants.OP_CHECKSIG.to_bytes(1, "little")
    )


def p2pkh_script_sig(sig: bytes, pk: bytes):
    """
    <sig> <pubkey>
    Args:
        sig: bytes, signature
        pk: bytes, public key
    """
    return len(sig).to_bytes(1, "little") + sig + len(pk).to_bytes(1, "little") + pk


def p2pk_script_pubkey(pk: bytes) -> bytes:
    return (
        len(pk).to_bytes(1, "little") + pk + constants.OP_CHECKSIG.to_bytes(1, "little")
    )


def p2pk_script_sig(sig: bytes) -> bytes:
    """
    <sig>
    """
    return len(sig).to_bytes(1, "little") + sig


def p2sh_script_pubkey(script_hash: bytes) -> bytes:
    """
    Args:
        script_hash: bytes, HASH160(redeemScript)
    """
    return (
        constants.OP_HASH160.to_bytes(1, "little")
        + len(script_hash).to_bytes(1, "little")
        + script_hash
        + constants.OP_EQUAL.to_bytes(1, "little")
    )


def p2sh_script_sig(sigs: typing.List[bytes], redeem_script: bytes) -> bytes:
    """
    https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#specification

    ...signatures... {serialized script}
    """
    script_sig = [len(sig).to_bytes(1, "little") + sig for sig in sigs]
    script_sig = b"".join(script_sig)
    script_sig += len(redeem_script).to_bytes(1, "little") + redeem_script
    return script_sig


def multisig_script_pubkey(m: int, pubkeys: typing.List[bytes]) -> bytes:
    """
    m-of-n multisig, n implied by length of pubkeys list
    Args:
        m: int, number of signatures required
        pubkeys: list[bytes], list of pubkeys for multisig
    """
    assert m in range(1, 17)
    n = len(pubkeys)
    assert n in range(1, 17)
    assert m <= n
    op_m = getattr(constants, f"OP_{m}")
    op_n = getattr(constants, f"OP_{n}")
    len_w_pubkeys = [len(pubkey).to_bytes(1, "big") + pubkey for pubkey in pubkeys]
    script_pubkey = (
        op_m.to_bytes(1, "big")
        + b"".join(len_w_pubkeys)
        + op_n.to_bytes(1, "big")
        + constants.OP_CHECKMULTISIG.to_bytes(1, "big")
    )
    return script_pubkey


def multisig_script_sig(sigs: typing.List[bytes]) -> bytes:
    len_w_sigs = [len(sig).to_bytes(1, "big") + sig for sig in sigs]
    return constants.OP_0.to_bytes(1, "big") + b"".join(len_w_sigs)


def null_data_script_pubkey(data: bytes) -> bytes:
    """
    Script pubkey for Null data
    https://developer.bitcoin.org/devguide/transactions.html#null-data
    """
    return constants.OP_RETURN.to_bytes(1, "big") + len(data).to_bytes(1, "big") + data


def p2sh_multisig_script_pubkey(m: int, pubkeys: typing.List[bytes]) -> bytes:
    return p2sh_script_pubkey(bits.script_hash(multisig_script_pubkey(m, pubkeys)))


def p2sh_multisig_script_sig(sigs: typing.List[bytes], redeem_script: bytes) -> bytes:
    # return multisig_script_sig(sigs) + redeem_script
    sigs_str = [sig.hex() for sig in sigs]
    return script(["OP_0"] + sigs_str + [redeem_script.hex()])


def p2wpkh_script_pubkey(pk_hash: bytes, witness_version: int = 0) -> bytes:
    """
    native p2wpkh
    https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wpkh

    Ex: (v0)
    witness: <sig> <pubkey>
    scriptSig: (empty)
    scriptPubKey: 0 <20-byte-key-hash>
                 (0x0014{20-byte-key-hash})
    """
    witness_version_opcode = getattr(constants, f"OP_{witness_version}")
    return (
        witness_version_opcode.to_bytes(1, "big")
        + len(pk_hash).to_bytes(1, "big")
        + pk_hash
    )


def p2wpkh_script_sig() -> bytes:
    return b""


def p2wsh_script_pubkey(witness_scripthash_: bytes, witness_version: int = 0) -> bytes:
    return p2wpkh_script_pubkey(witness_scripthash_, witness_version=witness_version)


def p2wsh_script_sig() -> bytes:
    return b""


def p2sh_p2wpkh_script_pubkey(pk_hash: bytes, witness_version: int = 0) -> bytes:
    return p2sh_script_pubkey(
        bits.script_hash(p2wpkh_script_pubkey(pk_hash, witness_version=witness_version))
    )


def p2sh_p2wpkh_script_sig(redeem_script):
    # redeem_script = p2wpkh_script_pubkey(pk_hash, witness_version=witness_version)
    return p2sh_script_sig([], redeem_script)


def p2sh_p2wsh_script_pubkey(witness_script: bytes, witness_version: int = 0):
    return p2sh_script_pubkey(
        bits.script_hash(
            p2wsh_script_pubkey(
                bits.witness_script_hash(witness_script),
                witness_version=witness_version,
            )
        )
    )


def p2sh_p2wsh_script_sig(witness_script: bytes):
    return p2sh_script_sig([], witness_script)


def script(args: typing.List[str], witness: bool = False) -> bytes:
    """
    Generic script
    Args:
        args: list, script ops / data
        witness: bool, wether witness script
    >>> script(["OP_2", "024c9b21035e4823d6f09d5a948201d14086d854dfa5bba828c06f5131d9cfe14f", "03fe0b5ca0ab60705b21a00cbd9900026f282c7188427123e87e0dc344ce742eb0", "02528e776c2bf0be68f4503151fd036c9cb720c4977f6f5b0248d5472c654aebe4", "OP_3", "OP_CHECKMULTISIG"]).hex()
    '5221024c9b21035e4823d6f09d5a948201d14086d854dfa5bba828c06f5131d9cfe14f2103fe0b5ca0ab60705b21a00cbd9900026f282c7188427123e87e0dc344ce742eb02102528e776c2bf0be68f4503151fd036c9cb720c4977f6f5b0248d5472c654aebe453ae'
    """
    scriptbytes = bits.compact_size_uint(len(args)) if witness else b""
    for arg in args:
        # arg is either OP or data
        if arg.startswith("OP_"):
            op = getattr(constants, arg)
            scriptbytes += op.to_bytes(1, "big")
        else:
            data = bytes.fromhex(arg)
            data_len = len(data)
            if not witness and data_len > 0x4B:
                data_len_min_bytes = (data_len.bit_length() + 7) // 8
                if data_len_min_bytes == 1:
                    no_bytes = 1
                    op_push = constants.OP_PUSHDATA1.to_bytes(1, "little")
                elif data_len_min_bytes == 2:
                    no_bytes = 2
                    op_push = constants.OP_PUSHDATA2.to_bytes(1, "little")
                elif data_len_min_bytes <= 4:
                    no_bytes = 4
                    op_push = constants.OP_PUSHDATA4.to_bytes(1, "little")
                else:
                    raise ValueError("too much data to push!")
                op_push += data_len.to_bytes(no_bytes, "little")
            else:
                op_push = len(data).to_bytes(1, "little")
            scriptbytes += op_push
            scriptbytes += data
    return scriptbytes


OP_INT_MAP = {
    op: getattr(constants, op) for op in dir(constants) if op.startswith("OP_")
}
INT_OP_MAP = {value: key for key, value in OP_INT_MAP.items()}


def decode_script(
    scriptbytes: bytes, witness: bool = False, parse: bool = False
) -> typing.Union[
    typing.List[str], typing.Tuple[typing.Union[typing.List[str], bytes], bytes]
]:
    """
    Decode Script. Decode witness script by using witness=True. When witness=True,
    you may use parse=True to parse first witness script instead of decoding.
    """
    decoded = []
    if witness:
        witness_stack_len, scriptbytes = bits.parse_compact_size_uint(scriptbytes)
        parsed_bytes = bits.compact_size_uint(witness_stack_len)

    while scriptbytes:
        if witness:
            push = scriptbytes[0]
            data = scriptbytes[1 : 1 + push]
            parsed_bytes += scriptbytes[: 1 + push]
            decoded.append(data.hex())
            scriptbytes = scriptbytes[1 + push :]
            witness_stack_len -= 1
            if not witness_stack_len:
                if parse:
                    return parsed_bytes, scriptbytes
                return decoded, scriptbytes
        elif scriptbytes[0] in range(1, 0x4C):
            push = scriptbytes[0]
            data = scriptbytes[1 : 1 + push]
            decoded.append(data.hex())
            scriptbytes = scriptbytes[1 + push :]
        else:
            op_int = scriptbytes[0]
            op = INT_OP_MAP[op_int]
            scriptbytes = scriptbytes[1:]
            if op == "OP_PUSHDATA1":
                push = scriptbytes[0]
                decoded.append(scriptbytes[1 : 1 + push].hex())
                scriptbytes = scriptbytes[1 + push :]
            elif op == "OP_PUSHDATA2":
                push = int.from_bytes(scriptbytes[:2], "little")
                decoded.append(scriptbytes[2 : 2 + push].hex())
                scriptbytes = scriptbytes[2 + push :]
            elif op == "OP_PUSHDATA4":
                push = int.from_bytes(scriptbytes[:4], "little")
                decoded.append(scriptbytes[4 : 4 + push].hex())
                scriptbytes = scriptbytes[4 + push :]
            else:
                decoded.append(op)
            # below if is unreachable?
            if witness:
                witness_stack_len -= 1
            if witness and not witness_stack_len:
                return decoded, scriptbytes
    return decoded
