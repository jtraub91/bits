from typing import List

import bits.script.constants as constants
from bits.utils import script_hash


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
    Args:
        sig: bytes, signature
        pk: bytes, public key
    """
    return (
        (len(sig) + 1).to_bytes(1, "little")
        + sig
        + constants.SIGHASH_ALL.to_bytes(1, "little")
        + len(pk).to_bytes(1, "little")
        + pk
    )


def p2pk_script_pubkey(pk: bytes) -> bytes:
    return (
        len(pk).to_bytes(1, "little") + pk + constants.OP_CHECKSIG.to_bytes(1, "little")
    )


def p2pk_script_sig(sig: bytes) -> bytes:
    return (
        (len(sig) + 1).to_bytes(1, "little")
        + sig
        + constants.SIGHASH_ALL.to_bytes(1, "little")
    )


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


def p2sh_script_sig(sigs: List[bytes], redeem_script: bytes) -> bytes:
    script_sig = [
        (len(sig) + 1).to_bytes(1, "little")
        + sig
        + constants.SIGHASH_ALL.to_bytes(1, "little")
        for sig in sigs
    ]
    script_sig = b"".join(script_sig)
    script_sig += len(redeem_script).to_bytes(1, "little") + redeem_script
    return script_sig


def multisig_script_pubkey(m: int, n: int, pubkeys: List[bytes]) -> bytes:
    assert m in range(1, 17)
    assert n in range(1, 17)
    assert len(pubkeys) == n
    op_m = getattr(constants, f"OP_{m}")
    op_n = getattr(constants, f"OP_{n}")
    len_w_pubkeys = [len(pubkey).to_bytes(1, "big") + pubkey for pubkey in pubkeys]
    script_pubkey = op_m + b"".join(len_w_pubkeys) + op_n + constants.OP_CHECKMULTISIG
    return script_pubkey


def multisig_script_sig(sigs: List[bytes]) -> bytes:
    len_w_sigs = [len(sig).to_bytes(1, "big") + sig for sig in sigs]
    return constants.OP_0.to_bytes(1, "big") + b"".join(len_w_sigs)


def p2sh_multisig_script_pubkey(m: int, n: int, pubkeys: List[bytes]) -> bytes:
    return p2sh_script_pubkey(script_hash(multisig_script_pubkey(m, n, pubkeys)))


def p2sh_p2wpkh_script_pubkey():
    return


def p2sh_p2wpkh_script_sig():
    return


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


def p2wsh_script_pubkey(script_hash: bytes, witness_version: int = 0) -> bytes:
    return p2wpkh_script_pubkey(script_hash, witness_version=witness_version)


def p2wsh_script_sig() -> bytes:
    return b""
