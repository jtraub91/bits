"""
https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#example
"""
from bits.bips.bip143 import witness_digest
from bits.bips.bip143 import witness_message
from bits.script.constants import SIGHASH_ALL
from bits.script.constants import SIGHASH_SINGLE
from bits.script.utils import decode_script
from bits.script.utils import p2pk_script_sig
from bits.script.utils import script
from bits.tx import outpoint
from bits.tx import tx
from bits.tx import tx_deser
from bits.tx import txin
from bits.tx import txout
from bits.utils import hash256
from bits.utils import sig


def test_p2wpkh():
    unsigned_tx = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
    deserialized_tx, _ = tx_deser(bytes.fromhex(unsigned_tx))

    """
    The first input comes from an ordinary P2PK:
        scriptPubKey : 2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac value: 6.25
        private key  : bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866
    
    The second input comes from a P2WPKH witness program:
        scriptPubKey : 00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1, value: 6
        private key  : 619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9
        public key   : 025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357
    """

    txins = [
        txin(
            outpoint(bytes.fromhex(ti["txid"]), ti["vout"]),
            b"",
            sequence=bytes.fromhex(ti["sequence"]),
        )
        for ti in deserialized_tx["txins"]
    ]
    txouts = [
        txout(to["value"], bytes.fromhex(to["scriptpubkey"]))
        for to in deserialized_tx["txouts"]
    ]

    input_2_scriptpubkey = bytes.fromhex(
        "00"  # witness version
        + "14"  # OP_PUSHDATA20
        + "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1"  # witness program
    )
    input_2_witness_program = input_2_scriptpubkey[2:]
    scriptcode = script(
        [
            script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    input_2_witness_program.hex(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ).hex()
        ]
    )
    msg = witness_message(
        txins,
        1,
        int(6e8),
        scriptcode,
        txouts,
        version=deserialized_tx["version"],
        locktime=deserialized_tx["locktime"],
        sighash_flag=SIGHASH_ALL,
    )

    expected_hash_preimage = bytes.fromhex(
        "0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000"
    )
    assert msg.hex() == expected_hash_preimage.hex(), "hash preimage mismatch"

    sighash = witness_digest(msg)
    expected_sighash = bytes.fromhex(
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    )
    assert sighash.hex() == expected_sighash.hex(), "sighash data mismatch"

    input_2_private_key = bytes.fromhex(
        "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"
    )
    witness_signature = sig(
        input_2_private_key,
        msg,
        sighash_flag=SIGHASH_ALL,
    )

    input_1_scriptpubkey = bytes.fromhex(
        "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"
    )
    txins = [
        txin(
            outpoint(
                bytes.fromhex(deserialized_tx["txins"][0]["txid"]),
                deserialized_tx["txins"][0]["vout"],
            ),
            input_1_scriptpubkey,
            sequence=bytes.fromhex(deserialized_tx["txins"][0]["sequence"]),
        ),
        txin(
            outpoint(
                bytes.fromhex(deserialized_tx["txins"][1]["txid"]),
                deserialized_tx["txins"][1]["vout"],
            ),
            b"",
            sequence=bytes.fromhex(deserialized_tx["txins"][1]["sequence"]),
        ),
    ]
    tx_ = tx(
        txins,
        txouts,
        version=deserialized_tx["version"],
        locktime=deserialized_tx["locktime"],
    )
    input_1_private_key = bytes.fromhex(
        "bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866"
    )
    input_1_signature = sig(
        input_1_private_key,
        tx_,
        sighash_flag=SIGHASH_ALL,
    )
    input_1_scriptsig = p2pk_script_sig(input_1_signature)
    txins = [
        txin(
            outpoint(
                bytes.fromhex(deserialized_tx["txins"][0]["txid"]),
                deserialized_tx["txins"][0]["vout"],
            ),
            input_1_scriptsig,
            sequence=bytes.fromhex(deserialized_tx["txins"][0]["sequence"]),
        ),
        txin(
            outpoint(
                bytes.fromhex(deserialized_tx["txins"][1]["txid"]),
                deserialized_tx["txins"][1]["vout"],
            ),
            b"",
            sequence=bytes.fromhex(deserialized_tx["txins"][1]["sequence"]),
        ),
    ]
    input_2_pubkey = bytes.fromhex(
        "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
    )
    input_2_witness_script = b"\x02" + script(
        [
            witness_signature.hex(),
            input_2_pubkey.hex(),
        ]
    )
    tx_ = tx(
        txins,
        txouts,
        version=deserialized_tx["version"],
        locktime=deserialized_tx["locktime"],
        script_witnesses=[
            b"\x00",
            input_2_witness_script,
        ],
    )
    expected_signed_transaction = bytes.fromhex(
        "01000000"
        + "00"
        + "01"
        + "02"
        + "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
        + "00000000"
        + format(len(input_1_scriptsig), "02x")
        + input_1_scriptsig.hex()
        + "eeffffff"
        + "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"
        + "01000000"
        + "00"
        + "ffffffff"
        + "02"
        + "202cb20600000000"
        + "1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
        + "9093510d00000000"
        + "1976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"
        + "00"
        + "02"
        + format(len(witness_signature), "02x")
        + witness_signature.hex()
        + "21025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
        + "11000000"
    )
    assert tx_.hex() == expected_signed_transaction.hex()


def test_p2sh_p2wpkh():
    unsigned_transaction = bytes.fromhex(
        "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
    )
    deserialized_tx, _ = tx_deser(unsigned_transaction)

    """
    The input comes from a P2SH-P2WPKH witness program:
        scriptPubKey : a9144733f37cf4db86fbc2efed2500b4f4e49f31202387, value: 10
        redeemScript : 001479091972186c449eb1ded22b78e40d009bdf0089
        private key  : eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf
        public key   : 03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873
    """
    outpoint_index = 0
    outpoint_value = int(10e8)
    outpoint_scriptpubkey = bytes.fromhex(
        "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"
    )
    outpoint_redeem_script = bytes.fromhex(
        "00"  # witness v0
        + "14"  # length of witness program = 20 => p2wpkh
        + "79091972186c449eb1ded22b78e40d009bdf0089"
    )
    outpoint_witness_program = outpoint_redeem_script[2:]
    scriptcode = script(
        [
            script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    outpoint_witness_program.hex(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ).hex()
        ]
    )

    outpoint_pubkey = bytes.fromhex(
        "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
    )

    txins = [
        txin(
            outpoint(bytes.fromhex(ti["txid"]), ti["vout"]),
            script(
                [outpoint_redeem_script.hex()]
            ),  # ignored in bits.bips.bi143.witness_message
            sequence=bytes.fromhex(ti["sequence"]),
        )
        for ti in deserialized_tx["txins"]
    ]
    txouts = [
        txout(to["value"], bytes.fromhex(to["scriptpubkey"]))
        for to in deserialized_tx["txouts"]
    ]
    msg = witness_message(
        txins,
        outpoint_index,
        outpoint_value,
        scriptcode,
        txouts,
        version=deserialized_tx["version"],
        locktime=deserialized_tx["locktime"],
        sighash_flag=SIGHASH_ALL,
    )
    expected_hash_preimage = bytes.fromhex(
        "01000000b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001976a91479091972186c449eb1ded22b78e40d009bdf008988ac00ca9a3b00000000feffffffde984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c839204000001000000"
    )
    assert (
        msg.hex() == expected_hash_preimage.hex()
    ), "mismatch for expected hash preimage"

    digest = witness_digest(msg)
    expected_sighash = bytes.fromhex(
        "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
    )
    assert digest.hex() == expected_sighash.hex(), "mismatch for expected sighash"

    private_key = bytes.fromhex(
        "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf"
    )
    signature = sig(private_key, msg, sighash_flag=SIGHASH_ALL)
    signed_tx = tx(
        txins,
        txouts,
        version=deserialized_tx["version"],
        locktime=deserialized_tx["locktime"],
        script_witnesses=[b"\x02" + script([signature.hex(), outpoint_pubkey.hex()])],
    )
    expected_signed_transaction = bytes.fromhex(
        "01000000"
        + "00"
        + "01"
        + "01"
        + "db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477"
        + "01000000"
        + "1716001479091972186c449eb1ded22b78e40d009bdf0089"
        + "feffffff"
        + "02"
        + "b8b4eb0b00000000"
        + "1976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac"
        + "0008af2f00000000"
        + "1976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac"
        + "02"
        + format(len(signature), "02x")
        + signature.hex()
        + "2103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
        + "92040000"
    )
    assert (
        signed_tx.hex() == expected_signed_transaction.hex()
    ), "mismatch for expected signed transaction"


def test_p2wsh_1():
    unsigned_transaction = bytes.fromhex(
        "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000"
    )
    deserialized_tx, _ = tx_deser(unsigned_transaction)

    """
    The first input comes from an ordinary P2PK:
        scriptPubKey: 21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac value: 1.5625
        private key:  b8f28a772fccbf9b4f58a4f027e07dc2e35e7cd80529975e292ea34f84c4580c
        signature:    304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201 (SIGHASH_ALL)

    The second input comes from a native P2WSH witness program:
        scriptPubKey : 00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0, value: 49
        witnessScript: 21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac
                        <026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae> CHECKSIGVERIFY CODESEPARATOR <0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465> CHECKSIG

    """
    input_0_scriptpubkey = bytes.fromhex(
        "21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac"
    )
    input_0_value = int(1.5625e8)
    input_0_private_key = bytes.fromhex(
        "b8f28a772fccbf9b4f58a4f027e07dc2e35e7cd80529975e292ea34f84c4580c"
    )
    input_0_sig = bytes.fromhex(
        "304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201"
    )

    outpoint_index = 1
    outpoint_value = int(49e8)
    outpoint_scriptpubkey = bytes.fromhex(
        "00"  # witness v0
        + "20"  # length of witness program = 32 => p2wsh
        + "5d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"
    )
    outpoint_witness_program = outpoint_scriptpubkey[2:]
    outpoint_witness_script = bytes.fromhex(
        "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
    )
    scriptcode = script([outpoint_witness_script.hex()])
    decoded_witness_script = decode_script(outpoint_witness_script)
    # decoded_witness_script = [
    #    "026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae",
    #    "OP_CHECKSIGVERIFY",
    #    "OP_CODESEPARATOR",
    #    "0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465",
    #    "OP_CHECKSIG"
    # ]
    txins = [
        txin(
            outpoint(
                bytes.fromhex(deserialized_tx["txins"][0]["txid"]),
                deserialized_tx["txins"][0]["vout"],
            ),
            script([input_0_sig.hex()]),
            sequence=bytes.fromhex(deserialized_tx["txins"][0]["sequence"]),
        ),
        txin(
            outpoint(
                bytes.fromhex(deserialized_tx["txins"][1]["txid"]),
                deserialized_tx["txins"][1]["vout"],
            ),
            b"",
            sequence=bytes.fromhex(deserialized_tx["txins"][1]["sequence"]),
        ),
    ]
    txouts = [
        txout(to["value"], bytes.fromhex(to["scriptpubkey"]))
        for to in deserialized_tx["txouts"]
    ]
    msg = witness_message(
        txins,
        outpoint_index,
        outpoint_value,
        scriptcode,
        txouts,
        version=deserialized_tx["version"],
        locktime=deserialized_tx["locktime"],
        sighash_flag=SIGHASH_SINGLE,
    )
    expected_hash_preimage = bytes.fromhex(
        "01000000ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d4100000000000000000000000000000000000000000000000000000000000000000815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f8000000004721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac0011102401000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000003000000"
    )
    assert (
        msg.hex() == expected_hash_preimage.hex()
    ), "mismatch for expected hash preimage"

    expected_sighash = bytes.fromhex(
        "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391"
    )
    assert (
        witness_digest(msg).hex() == expected_sighash.hex()
    ), "mismatch for expected sighash"

    # 026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae private key
    private_key_1 = bytes.fromhex(
        "8e02b539b1500aa7c81cf3fed177448a546f19d2be416c0c61ff28e577d8d0cd"
    )
    signature_1 = sig(private_key_1, msg, sighash_flag=SIGHASH_SINGLE)

    decoded_witness_script = decoded_witness_script[
        decoded_witness_script.index("OP_CODESEPARATOR") + 1 :
    ]
    outpoint_witness_script_prime = script(decoded_witness_script)
    scriptcode = script([outpoint_witness_script_prime.hex()])
    msg = witness_message(
        txins,
        outpoint_index,
        outpoint_value,
        scriptcode,
        txouts,
        version=deserialized_tx["version"],
        locktime=deserialized_tx["locktime"],
        sighash_flag=SIGHASH_SINGLE,
    )
    expected_hash_preimage = bytes.fromhex(
        "01000000ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d4100000000000000000000000000000000000000000000000000000000000000000815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000023210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac0011102401000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000003000000"
    )
    assert (
        msg.hex() == expected_hash_preimage.hex()
    ), "mismatch for expected hash pre-image post-op-codeseparator"
    expected_sighash = bytes.fromhex(
        "fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47"
    )
    assert (
        witness_digest(msg).hex() == expected_sighash.hex()
    ), "mismatch for expected sighash post-op-codeseparator"

    # 0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465 private key
    private_key_2 = bytes.fromhex(
        "86bf2ed75935a0cbef03b89d72034bb4c189d381037a5ac121a70016db8896ec"
    )
    signature_2 = sig(private_key_2, msg, sighash_flag=SIGHASH_SINGLE)
    tx_ = tx(
        txins,
        txouts,
        version=deserialized_tx["version"],
        locktime=deserialized_tx["locktime"],
        script_witnesses=[
            b"\x00",
            b"\x03"
            + script(
                [signature_2.hex(), signature_1.hex(), outpoint_witness_script.hex()]
            ),
        ],
    )
    expected_signed_tx = bytes.fromhex(
        "01000000"
        + "00"
        + "01"
        + "02"
        + "fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e"
        + "00000000"
        + "48"
        + "47"
        + "304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201"
        + "ffffffff"
        + "0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f8"
        + "00000000"
        + "00"
        + "ffffffff"
        + "01"
        + "00f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac"
        + "00"
        + "03"
        + format(len(signature_2), "02x")
        + signature_2.hex()
        + format(len(signature_1), "02x")
        + signature_1.hex()
        + "47"
        + "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
        + "00000000"
    )
    assert (
        tx_.hex() == expected_signed_tx.hex()
    ), "mismatch for expected signed transaction"


def test_p2wsh_2():
    raise NotImplementedError


def test_p2sh_p2wsh():
    raise NotImplementedError


def test_no_find_and_delete():
    raise NotImplementedError
