from typing import List

from bits.script.constants import OP_CHECKSIG
from bits.script.constants import OP_DUP
from bits.script.constants import OP_EQUAL
from bits.script.constants import OP_EQUALVERIFY
from bits.script.constants import OP_HASH160
from bits.script.constants import SIGHASH_ALL


def p2pkh_script_pubkey(pk_hash: bytes) -> bytes:
    return (
        OP_DUP.to_bytes(1, "little")
        + OP_HASH160.to_bytes(1, "little")
        + len(pk_hash).to_bytes(1, "little")
        + pk_hash
        + OP_EQUALVERIFY.to_bytes(1, "little")
        + OP_CHECKSIG.to_bytes(1, "little")
    )


def p2pkh_script_sig(sig: bytes, pk: bytes):
    """
    Args:
        sig: bytes, signature
        pk: bytes, public key
    """
    return (
        (len(sig) + 1).to_bytes(1, "little")
        + sig
        + SIGHASH_ALL.to_bytes(1, "little")
        + len(pk).to_bytes(1, "little")
        + pk
    )


def p2pk_script_pubkey(pk: bytes) -> bytes:
    return len(pk).to_bytes(1, "little") + pk + OP_CHECKSIG.to_bytes(1, "little")


def p2pk_script_sig(sig: bytes) -> bytes:
    return (
        (len(sig) + 1).to_bytes(1, "little") + sig + SIGHASH_ALL.to_bytes(1, "little")
    )


def p2sh_script_pubkey(script_hash: bytes) -> bytes:
    """
    Args:
        script_hash: bytes, HASH160(redeemScript)
    """
    return (
        OP_HASH160.to_bytes(1, "little")
        + len(script_hash).to_bytes(1, "little")
        + script_hash
        + OP_EQUAL.to_bytes(1, "little")
    )


def p2sh_script_sig(sigs: List[bytes], redeem_script: bytes) -> bytes:
    script_sig = [
        (len(sig) + 1).to_bytes(1, "little") + sig + SIGHASH_ALL.to_bytes(1, "little")
        for sig in sigs
    ]
    script_sig = b"".join(script_sig)
    script_sig += len(redeem_script).to_bytes(1, "little") + redeem_script
    return script_sig
