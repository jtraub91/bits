"""
https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki

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
"""
import hashlib
from typing import List, Optional, Union


def witness_message(
    txins: List[bytes],
    txin_index: int,
    txin_value: Union[int, float],
    scriptcode: bytes,
    txouts: List[bytes],
    version: int = 1,
    locktime: int = 0,
    sighash_flag: Optional[int] = None,
) -> bytes:
    """
    Generate witness message (pre-imagehash) from txins, txouts, outpoint info, and other tx details
    Hashprevouts, hashsequence, scriptcode, hashoutputs, etc. calculated as necessary
    Note that even though it is provided as input,
        the full txin is not serialized as per the traditional signature digest algorithm.
    Args:
        txins: list[bytes], inputs
        txin_index: int, index corresponding to txins for the outpoint we are signing
        txin_value: int, value of outpoint in which we are signing, in satoshis
        scriptcode: bytes, scriptcode of the input
            if p2wpkh, scriptcode = OP_DUP OP_HASH160 <witness-program> OP_EQUALVERIFY OP_CHECKSIG
            if p2wsh, scriptcode = <witness-script>
                see tests/unit/test_bip143.py for handling of OP_CODESEPARATOR in witness script
        txouts: list[bytes], outputs
        version: int, version
        locktime: int, locktime
    """
    outpoints = [txin[:36] for txin in txins]

    anyone_can_pay = sighash_flag & 0x80
    if anyone_can_pay:
        hash_prevouts = b"\x00" * 32
    else:
        hash_prevouts = hashlib.sha256(
            hashlib.sha256(b"".join(outpoints)).digest()
        ).digest()

    sequences = [txin[-4:] for txin in txins]
    if sighash_flag in [0x02, 0x03, 0x81, 0x82, 0x83]:
        # SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL|SIGHASH_ANYONECANPAY,
        # SIGHASH_NONE|SIGHASH_ANYONECANPAY, SIGHASH_SINGLE|SIGHASH_ANYONECANPAY
        hash_sequence = b"\x00" * 32
    else:
        hash_sequence = hashlib.sha256(
            hashlib.sha256(b"".join(sequences)).digest()
        ).digest()

    outpoint = outpoints[txin_index]
    sequence = sequences[txin_index]

    if sighash_flag & 0x7F not in [0x02, 0x03]:
        # not SIGHASH_NONE or SIGHASH_SINGLE
        hash_outputs = hashlib.sha256(
            hashlib.sha256(b"".join(txouts)).digest()
        ).digest()
    elif sighash_flag & 0x7F == 0x03 and txin_index < len(txouts):
        # SIGHASH_SINGLE
        # "If sighash type is SINGLE and the input index is smaller than the number of outputs,
        # hashOutputs is the double SHA256 of the output amount with scriptPubKey of the same index as the input;"
        hash_outputs = hashlib.sha256(
            hashlib.sha256(txouts[txin_index]).digest()
        ).digest()
    else:
        hash_outputs = b"\x00" * 32

    msg = (
        version.to_bytes(4, "little")
        + hash_prevouts
        + hash_sequence
        + outpoint
        + scriptcode
        + int(txin_value).to_bytes(8, "little")
        + sequence
        + hash_outputs
        + locktime.to_bytes(4, "little")
    )
    if sighash_flag is not None:
        msg += sighash_flag.to_bytes(4, "little")
    return msg


def witness_digest(witness_msg: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(witness_msg).digest()).digest()
