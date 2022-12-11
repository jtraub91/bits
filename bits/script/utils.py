from bits.script.constants import OP_CHECKSIG
from bits.script.constants import OP_DUP
from bits.script.constants import OP_EQUALVERIFY
from bits.script.constants import OP_HASH160


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
