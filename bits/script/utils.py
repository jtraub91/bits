from typing import List

import bits.script.constants as constants
from bits.base58 import base58check_decode
from bits.bips.bip173 import decode_segwit_addr
from bits.utils import script_hash


def scriptpubkey(data: list, network: str = "mainnet") -> bytes:
    """
    Create scriptpubkey of various types. Infers type from data provided as input
    For use with corresponding cli method

    >>> scriptpubkey(["02726b45a5b1b506015dc926630b2627454d635d87eeb72bb7d5476d545d6769f9"])  # p2pk

    >>> scriptpubkey(["1GhhwzPms6aKhzK5EcSYdeJ8T35BvAsn7y"])  # p2pkh

    >>> scriptpubkey([
            2,
            "03ffe6319b68b781d654e32b7b068e946eef2b0f094ba9eeb84308c6c58af71208",
            "03377714f72611b81ee5dfbe6f52bfe0e9b1f6827ca00b6ab90d899720b1df00fd",
            "02726b45a5b1b506015dc926630b2627454d635d87eeb72bb7d5476d545d6769f9"
        ])  # multisig

    >>> scriptpubkey(["bc1q4s7tflrwuenru6tuwsa26rvflk8tfs2lk5gysg"])    # p2wpkh

    """
    if len(data) == 1:
        data = data[0]
        # data is either pubkey, base58check, or segwit
        if data.startswith("0"):
            # pubkey
            data = bytes.fromhex(data)
            assert data[0] in [2, 3, 4], "invalid pubkey version"
            if data[0] in [2, 3]:
                assert len(data) == 33, "invalid length for compressed pubkey"
            else:
                assert len(data) == 65, "invalid length for uncompressed pubkey"
            return p2pk_script_pubkey(data)
        else:
            data = data.encode("ascii")
            if data[0:1] in [b"1", b"3", b"m", b"n", b"2"]:
                # base58check address
                decoded = base58check_decode(data)
                version, payload = decoded[0:1], decoded[1:]
                if version == b"\x00":
                    network = "mainnet"
                    addr_type = "p2pkh"
                elif version == b"\x05":
                    network = "mainnet"
                    addr_type = "p2sh"
                elif version == b"\x6f":
                    network = "testnet"
                    addr_type = "p2pkh"
                elif version == b"\xc4":
                    network = "testnet"
                    addr_type = "p2sh"
                else:
                    raise ValueError("unrecognized base58check version byte")
                # assert network == bitsconfig["network"], "network version mismatch"
                if addr_type == "p2pkh":
                    script_pubkey = p2pkh_script_pubkey(payload)
                else:
                    # p2sh
                    script_pubkey = p2sh_script_pubkey(payload)
                return script_pubkey
            else:
                # segwit
                hrp, witness_version, witness_program = decode_segwit_addr(data)
                # if bitsconfig["network"] == "mainnet":
                #     assert hrp == b"bc", "hrp network version mismatch"
                # elif bitsconfig["network"] == "testnet":
                #     assert hrp == b"tb", "hrp network version mismatch"
                if len(witness_program) == 20:
                    return p2wpkh_script_pubkey(
                        witness_program, witness_version=witness_version
                    )
                elif len(witness_program) == 32:
                    return p2wsh_script_pubkey(
                        witness_program, witness_version=witness_version
                    )
                return
    else:
        m = int(data[0])
        pubkeys = [bytes.fromhex(pk) for pk in data[1:]]
        return multisig_script_pubkey(m, pubkeys)


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
    """
    <sig>
    """
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
    """
    https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#specification

    ...signatures... {serialized script}
    """
    script_sig = [
        (len(sig) + 1).to_bytes(1, "little")
        + sig
        + constants.SIGHASH_ALL.to_bytes(1, "little")
        for sig in sigs
    ]
    script_sig = b"".join(script_sig)
    script_sig += len(redeem_script).to_bytes(1, "little") + redeem_script
    return script_sig


def multisig_script_pubkey(m: int, pubkeys: List[bytes]) -> bytes:
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


def multisig_script_sig(sigs: List[bytes]) -> bytes:
    len_w_sigs = [len(sig).to_bytes(1, "big") + sig for sig in sigs]
    return constants.OP_0.to_bytes(1, "big") + b"".join(len_w_sigs)


def null_data_script_pubkey(data: bytes):
    """
    Script pubkey for Null data
    https://developer.bitcoin.org/devguide/transactions.html#null-data
    """
    return constants.OP_RETURN + len(data).to_bytes(1, "big") + data


def p2sh_multisig_script_pubkey(m: int, pubkeys: List[bytes]) -> bytes:
    return p2sh_script_pubkey(script_hash(multisig_script_pubkey(m, pubkeys)))


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


def script(args: list) -> bytes:
    """
    Generic script
    Args:
        args: list, script ops / data
    >>> script(["OP_2", "03ffe6319b68b781d654e32b7b068e946eef2b0f094ba9eeb84308c6c58af71208", "03377714f72611b81ee5dfbe6f52bfe0e9b1f6827ca00b6ab90d899720b1df00fd", "02726b45a5b1b506015dc926630b2627454d635d87eeb72bb7d5476d545d6769f9", "OP_3"])
    """
    scriptbytes = b""
    for arg in args:
        # arg is either OP or data
        if arg.startswith("OP_"):
            op = getattr(constants, arg)
            scriptbytes += op.to_bytes(1, "big")
        else:
            data = bytes.fromhex(arg)
            scriptbytes += len(data).to_bytes(1, "big")
            scriptbytes += data
    return scriptbytes
