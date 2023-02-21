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
from typing import List
from typing import Optional
from typing import Union


def witness_message(
    txins: List[bytes],
    outpoint_txin_index: int,
    outpoint_value: Union[int, float],
    outpoint_scriptpubkey: bytes,
    txouts: List[bytes],
    version: int = 1,
    locktime: int = 0,
    sighash_flag: Optional[int] = None,
) -> bytes:
    """
    Args:
        txins: list[bytes], transaction inputs
        outpoint_txin_index: int, index corresponding to txins for the outpoint we are signing
        outpoint_value: int, value of outpoint in which we are signing, in satoshis
        txouts: list[bytes], transaction outputs
        version: int, transaction version
        locktime: int, transactionlocktime
    """
    outpoints = [txin[:36] for txin in txins]
    hash_prevouts = hashlib.sha256(
        hashlib.sha256(b"".join(outpoints)).digest()
    ).digest()

    sequences = [txin[-4:] for txin in txins]
    hash_sequence = hashlib.sha256(
        hashlib.sha256(b"".join(sequences)).digest()
    ).digest()

    outpoint = outpoints[outpoint_txin_index]
    assert (
        outpoint_scriptpubkey[0] == 0
    ), "outpoint_scriptpubkey is not v0 witness program"
    if outpoint_scriptpubkey[1] == 20:
        # p2wpkh
        scriptcode = b"\x19\x76\xa9\x14" + outpoint_scriptpubkey[2:] + b"\x88\xac"
    elif outpoint_scriptpubkey[1] == 32:
        # p2wsh
        raise NotImplementedError("p2wsh scriptcode")
    else:
        raise ValueError("outpoint scriptpubkey not identified as p2wpkh nor p2wsh")
    sequence = sequences[outpoint_txin_index]

    hash_outputs = hashlib.sha256(hashlib.sha256(b"".join(txouts)).digest()).digest()

    msg = (
        version.to_bytes(4, "little")
        + hash_prevouts
        + hash_sequence
        + outpoint
        + scriptcode
        + int(outpoint_value).to_bytes(8, "little")
        + sequence
        + hash_outputs
        + locktime.to_bytes(4, "little")
    )
    if sighash_flag is not None:
        msg += sighash_flag.to_bytes(4, "little")
    return msg


def witness_digest(witness_msg: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(witness_msg).digest()).digest()
