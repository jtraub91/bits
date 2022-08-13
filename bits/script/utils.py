from bits.script.constants import OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG


def p2pkh_script_pubkey(pk_hash: bytes) -> bytes:
    return (
        OP_DUP.to_bytes(1, "little")
        + OP_HASH160.to_bytes(1, "little")
        + len(pk_hash).to_bytes(1, "little")
        + pk_hash
        + OP_EQUALVERIFY.to_bytes(1, "little")
        + OP_CHECKSIG.to_bytes(1, "little")
    )
