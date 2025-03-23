import typing
from collections import deque

import bits.base58
import bits.constants
import bits.crypto
import bits.ecmath
import bits.pem
import bits.tx
from bits.tx import Tx


def scriptpubkey(data: bytes) -> bytes:
    """
    Create scriptpubkey by inferring input data type
    Supports data as pubkey, base58check, or segwit

    Args:
        data: bytes, pubkey, base58check, or segwit address

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
    """
    if bits.ecmath.is_point(data):
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
    elif bits.is_segwit_addr(data):
        hrp, witness_version, witness_program = bits.decode_segwit_addr(data)
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
        raise ValueError("data not identified as pubkey, base58check, nor segwit")


def p2pkh_script_pubkey(pk_hash: bytes) -> bytes:
    return (
        bits.constants.OP_DUP.to_bytes(1, "little")
        + bits.constants.OP_HASH160.to_bytes(1, "little")
        + len(pk_hash).to_bytes(1, "little")
        + pk_hash
        + bits.constants.OP_EQUALVERIFY.to_bytes(1, "little")
        + bits.constants.OP_CHECKSIG.to_bytes(1, "little")
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
        len(pk).to_bytes(1, "little")
        + pk
        + bits.constants.OP_CHECKSIG.to_bytes(1, "little")
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
        bits.constants.OP_HASH160.to_bytes(1, "little")
        + len(script_hash).to_bytes(1, "little")
        + script_hash
        + bits.constants.OP_EQUAL.to_bytes(1, "little")
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
    op_m = getattr(bits.constants, f"OP_{m}")
    op_n = getattr(bits.constants, f"OP_{n}")
    len_w_pubkeys = [len(pubkey).to_bytes(1, "big") + pubkey for pubkey in pubkeys]
    script_pubkey = (
        op_m.to_bytes(1, "big")
        + b"".join(len_w_pubkeys)
        + op_n.to_bytes(1, "big")
        + bits.constants.OP_CHECKMULTISIG.to_bytes(1, "big")
    )
    return script_pubkey


def multisig_script_sig(sigs: typing.List[bytes]) -> bytes:
    len_w_sigs = [len(sig).to_bytes(1, "big") + sig for sig in sigs]
    return bits.constants.OP_0.to_bytes(1, "big") + b"".join(len_w_sigs)


def null_data_script_pubkey(data: bytes) -> bytes:
    """
    Script pubkey for Null data
    https://developer.bitcoin.org/devguide/transactions.html#null-data
    """
    return (
        bits.constants.OP_RETURN.to_bytes(1, "big")
        + len(data).to_bytes(1, "big")
        + data
    )


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

    pk_hash must be 20 bytes for v0 native p2wpkh

    Ex: (v0)
    witness: <sig> <pubkey>
    scriptSig: (empty)
    scriptPubKey: 0 <20-byte-key-hash>
                 (0x0014{20-byte-key-hash})
    """
    witness_version_opcode = getattr(bits.constants, f"OP_{witness_version}")
    return (
        witness_version_opcode.to_bytes(1, "big")
        + len(pk_hash).to_bytes(1, "big")
        + pk_hash
    )


def p2wpkh_script_sig() -> bytes:
    return b""


def p2wsh_script_pubkey(witness_scripthash_: bytes, witness_version: int = 0) -> bytes:
    """
    witness_scripthash_ must be 32 bytes for v0 native p2wsh
    """
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
            op = getattr(bits.constants, arg)
            scriptbytes += op.to_bytes(1, "big")
        else:
            data = bytes.fromhex(arg)
            data_len = len(data)
            if data_len == 0:
                continue
            if not witness and data_len > 0x4B:
                data_len_min_bytes = (data_len.bit_length() + 7) // 8
                if data_len_min_bytes == 1:
                    no_bytes = 1
                    op_push = bits.constants.OP_PUSHDATA1.to_bytes(1, "little")
                elif data_len_min_bytes == 2:
                    no_bytes = 2
                    op_push = bits.constants.OP_PUSHDATA2.to_bytes(1, "little")
                elif data_len_min_bytes <= 4:
                    no_bytes = 4
                    op_push = bits.constants.OP_PUSHDATA4.to_bytes(1, "little")
                else:
                    raise ValueError("too much data to push!")
                op_push += data_len.to_bytes(no_bytes, "little")
            else:
                op_push = len(data).to_bytes(1, "little")
            scriptbytes += op_push
            scriptbytes += data
    return scriptbytes


OP_INT_MAP = {
    op: getattr(bits.constants, op)
    for op in dir(bits.constants)
    if op.startswith("OP_")
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
    # TODO: maybe refactor this?
    # logic is a little weird with the witness and parse flags,
    # and script probably needs to be decoded during eval_script
    # maybe this function is better to be refactored to "parse_script"
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


def check_sig(
    sig_: bytes, pubkey_: bytes, scriptcode_: bytes, tx_: bytes, txin_n: int
) -> bool:
    """
    Check signature
    Args:
        sig_: bytes, signature
        pubkey_: bytes, pubkey
        scriptcode_: bytes, scriptcode inserted
        tx_: bytes, transaction
        txin_n: int, index of input in transaction
    Returns:
        True if signature verification passes, else False
    """
    tx_dict, _ = bits.tx.tx_deser(tx_)

    # insert scriptcode for scriptsig for the txin
    txin_ = tx_dict["txins"][txin_n]
    txin_["scriptsig"] = scriptcode_.hex()

    hashtype = sig_[-1]

    anyone_can_pay = hashtype & bits.constants.SIGHASH_ANYONECANPAY
    sighash = hashtype & 0x03
    if sighash == bits.constants.SIGHASH_ALL:
        # all outputs are included
        pass
    elif sighash == bits.constants.SIGHASH_NONE:
        # no outputs included
        tx_dict["txouts"] = []
    elif sighash == bits.constants.SIGHASH_SINGLE:
        # only the output with same index as this txin is included
        txouts = tx_dict["txouts"]
        tx_dict["txouts"] = [txouts[txin_n]]
    else:
        raise ValueError(f"sighash value not recognized: {sighash}")
    if anyone_can_pay:
        # only include this txin
        tx_dict["txins"] = [tx_dict["txins"][txin_n]]

    # re-serialize tx bytes from tx_dict
    # TODO: split this out to function
    # this is a reason we should re-factor and abstract to Tx class
    # see https://github.com/jtraub91/bits/issues/15
    txin_dicts = tx_dict["txins"]
    txout_dicts = tx_dict["txouts"]
    version = tx_dict["version"]
    locktime = tx_dict["locktime"]
    txins_ = []
    for txin_dict in txin_dicts:
        txin_ = bits.tx.txin(
            bits.tx.outpoint(bytes.fromhex(txin_dict["txid"])[::-1], txin_dict["vout"]),
            bytes.fromhex(txin_dict["scriptsig"]),
            sequence=bytes.fromhex(txin_dict["sequence"]),
        )
        txins_.append(txin_)
    txouts_ = []
    for txout_dict in txout_dicts:
        txout_ = bits.tx.txout(
            txout_dict["value"], bytes.fromhex(txout_dict["scriptpubkey"])
        )
        txouts_.append(txout_)

    msg_preimage = bits.tx.tx(
        txins_, txouts_, version=version, locktime=locktime
    ) + hashtype.to_bytes(4, "little")
    if sig_verify(sig_, pubkey_, msg_preimage, msg_preimage=True) == "OK":
        return True
    return False


def eval_script(script_: bytes, tx_: bytes, txin_n: int) -> bool:
    """
    Evalute script for txin n in tx
    https://github.com/bitcoin/bitcoin/blob/v0.2.13/script.cpp#L44
    Arg:
        script_: bytes, script
        tx_: bytes, transaction
        txin_n: int, txin index for which we are evaluating script for
    Returns:
        True if script succeeds, else False
    """
    scriptbytes = script_
    scriptbytes_index = 0

    begin_script_code = 0
    end_script_code = len(scriptbytes)

    stack = deque([])
    while scriptbytes:
        op = scriptbytes[0]
        scriptbytes = scriptbytes[1:]
        scriptbytes_index += 1
        if op == bits.constants.OP_0:
            stack.append(b"")
        elif op in range(1, 0x4C):
            # op interpreted as OP_PUSHBYTES_x
            data = scriptbytes[:op]
            scriptbytes = scriptbytes[op:]
            scriptbytes_index += op
            stack.append(data)
        elif op == bits.constants.OP_PUSHDATA1:
            push = scriptbytes[0]
            data = scriptbytes[1 : 1 + push]
            scriptbytes = scriptbytes[1 + push :]
            scriptbytes_index += 1 + push
            stack.append(data)
        elif op == bits.constants.OP_PUSHDATA2:
            push = int.from_bytes(scriptbytes[:2], "little")
            data = scriptbytes[2 : 2 + push]
            scriptbytes = scriptbytes[2 + push :]
            scriptbytes_index += 2 + push
            stack.append(data)
        elif op == bits.constants.OP_PUSHDATA4:
            push = int.from_bytes(scriptbytes[:4], "little")
            data = scriptbytes[4 : 4 + push]
            scriptbytes = scriptbytes[4 + push :]
            scriptbytes_index += 4 + push
            stack.append(data)
        elif op == bits.constants.OP_DUP:
            stack.append(stack[-1])
        elif op == bits.constants.OP_HASH160:
            item = stack.pop()
            stack.append(bits.crypto.hash160(item))
        elif op == bits.constants.OP_EQUALVERIFY:
            item1 = stack.pop()
            item2 = stack.pop()
            if item1 == item2:
                stack.append(1)
            else:
                stack.append(0)
            result = stack.pop()
            if not result:
                return False
        elif op == bits.constants.OP_CODESEPARATOR:
            begin_script_code = scriptbytes_index
        elif op in [
            bits.constants.OP_CHECKSIG,
            bits.constants.OP_CHECKSIGVERIFY,
        ]:
            if len(stack) < 2:
                return False
            pubkey_ = stack.pop()
            sig_ = stack.pop()

            script_code = script_[begin_script_code:end_script_code]

            # remove sig from script_code, since sig can't sign itself
            script_code = find_and_delete(sig_, script_code)

            result = check_sig(sig_, pubkey_, script_code, tx_, txin_n)
            stack.append(result)
            if op == bits.constants.OP_CHECKSIGVERIFY:
                result = stack.pop()
                if not result:
                    return False
        else:
            raise ValueError(f"op code not recognized: {op}")

    result = stack.pop()
    if result:
        return True
    return False


def find_and_delete(sig_: bytes, scriptcode_: bytes) -> bytes:
    """
    Find and delete signature (plus its preceding push op codes) from scriptcode
    Handles the case of multiple occurences of signature

    Used during eval_script (OP_CHECKSIG)
    Args:
        sig_: bytes, signature
        scriptcode_: bytes, scriptcode
    Returns:
        bytes: scriptcode with signature and opcodes deleted
    """

    while scriptcode_.find(sig_) != -1:
        # find first occurrence of sig_ in scriptcode_
        find_index = scriptcode_.find(sig_)

        # figure out preceding number of op push bytes based on sig length
        if len(sig_) < 0x4C:
            push_op_code_bytes_length = 1
        elif len(sig_) <= 0xFF:
            push_op_code_bytes_length = 2
        elif len(sig_) <= 0xFFFF:
            push_op_code_bytes_length = 3
        else:
            push_op_code_bytes_length = 5

        # remove preceding op code bytes
        scriptcode_ = (
            scriptcode_[: find_index - push_op_code_bytes_length]
            + scriptcode_[find_index:]
        )

        # remove first occurrence of sig_
        scriptcode_ = scriptcode_.replace(sig_, b"")

    return scriptcode_


def sig(
    key: bytes,
    msg: bytes,
    sighash_flag: typing.Optional[int] = None,
    msg_preimage: bool = False,
) -> bytes:
    """
    Create DER encoded Bitcoin signature from message, optional sighash_flag

    Sighash_flag gets appended to msg, this data is then hashed with HASH256,
        signed, and DER-encoded

    Args:
        key: bytes, private key
        msg: bytes,
        sighash_flag: Optional[int], appended to msg before HASH256
        msg_preimage: whether msg is pre-image or not
            pre-image already has 4 byte sighash flag appended
            if msg_preimage, msg is still hashed, and 1 byte sighash_flag still appended
            after signing/der-encoding
    Returns:
        bytes, signature(HASH256(msg + sighash_flag))
    """
    if not msg_preimage and sighash_flag is not None:
        msg += sighash_flag.to_bytes(4, "little")
    elif msg_preimage and sighash_flag is not None:
        sh_flag = int.from_bytes(msg[-4:], "little")
        assert (
            sh_flag == sighash_flag
        ), "sighash_flag parsed from msg preimage does not match provided sighash_flag argument"
    elif msg_preimage:
        sh_flag = int.from_bytes(msg[-4:], "little")
    sigdata = bits.crypto.hash256(msg)
    r, s = bits.ecmath.sign(
        bits.ecmath.privkey_int(key), int.from_bytes(sigdata, "big")
    )
    signature_der = bits.pem.der_encode_sig(r, s)
    if sighash_flag is not None:
        signature_der += sighash_flag.to_bytes(1, "little")
    elif msg_preimage:
        # if msg_preimage=True (msg preimage contains sighash flag) and sighash_flag not provided as arg
        signature_der += sh_flag.to_bytes(1, "little")
    return signature_der


def sig_verify(
    sig_: bytes, pubkey_: bytes, msg: bytes, msg_preimage: bool = False
) -> str:
    sighash_flag = sig_[-1]
    r, s = bits.pem.der_decode_sig(sig_[:-1])
    if not msg_preimage:
        msg += sighash_flag.to_bytes(4, "little")
    msg_digest = bits.crypto.hash256(msg)
    try:
        result = bits.ecmath.verify(
            r, s, bits.ecmath.point(pubkey_), int.from_bytes(msg_digest, "big")
        )
    except AssertionError as err:
        return err.args[0]
    return "OK"


def v0_witness_preimage(
    tx_: Tx, txin_index: int, txin_value: int, scriptcode: bytes, sighash_type: int
) -> bytes:
    """
    Preimage for v0 witness signatures
    per BIP 143,
    https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification

    Double SHA256 of the serialization of:
        1. nVersion of the transaction (4-byte little endian)
        2. hashPrevouts (32-byte hash)
        3. hashSequence (32-byte hash)
        4. outpoint (32-byte hash + 4-byte little endian)
        5. scriptCode of the input (serialized as scripts inside CTxOuts)
        6. value of the output spent by this input (8-byte little endian)
        7. nSequence of the input (4-byte little endian)
        8. hashOutputs (32-byte hash)
        9. nLocktime of the transaction (4-byte little endian)
        10. sighash type of the signature (4-byte little endian)

    Args:
        tx_: Tx, transaction
        txin_index: int, index of the tx input we are signing for
        txin_value: int, value of the tx input we are signing for (i.e. corresponding to txin_index)
        scriptcode: bytes, scriptcode of the tx input we are signing for (i.e. corresponding to txin_index)
        sighash_type: int, sighash type
    Returns:
        bytes, hash of witness preimage
    """
    prev_outpoints = b""
    prev_sequence = b""
    for txin_ in tx_["txins"]:
        prev_outpoints += txin_["outpoint"]
        prev_sequence += txin_["sequence"].to_bytes(4, "little")

    if sighash_type & bits.constants.SIGHASH_ANYONECANPAY:
        hash_prevouts = b"\x00" * 32
    else:
        hash_prevouts = bits.crypto.hash256(prev_outpoints)

    if (
        sighash_type & bits.constants.SIGHASH_ANYONECANPAY
        or (sighash_type & 0x1F) == bits.constants.SIGHASH_NONE
        or (sighash_type & 0x1F) == bits.constants.SIGHASH_SINGLE
    ):
        hash_sequence = b"\x00" * 32
    else:
        hash_sequence = bits.crypto.hash256(prev_sequence)

    outpoint = tx_["txins"][txin_index]["outpoint"]

    hash_outputs = b""
    if (sighash_type & 0x1F) != bits.constants.SIGHASH_SINGLE and (
        sighash_type & 0x1F
    ) != bits.constants.SIGHASH_NONE:
        for txout_ in tx_["txouts"]:
            hash_outputs += txout_
            print(txout_.hex())
        hash_outputs = bits.crypto.hash256(hash_outputs)
    elif (sighash_type & 0x1F) == bits.constants.SIGHASH_SINGLE and txin_index < len(
        tx_["txouts"]
    ):
        hash_outputs = bits.crypto.hash256(tx_["txouts"][txin_index])
    else:
        hash_outputs = b"\x00" * 32

    return (
        tx_["version"].to_bytes(4, "little")
        + hash_prevouts
        + hash_sequence
        + outpoint
        + scriptcode
        + txin_value.to_bytes(8, "little")
        + tx_["txins"][txin_index]["sequence"].to_bytes(4, "little")
        + hash_outputs
        + tx_["locktime"].to_bytes(4, "little")
        + sighash_type.to_bytes(4, "little")
    )
