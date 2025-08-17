"""
https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#example
"""
import bits.crypto
import bits.keys
import bits.ecmath
import bits.script
import bits.tx
from bits import constants
from bits.tx import Tx


def test_p2wpkh():
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
    unsigned_tx = Tx(
        bytes.fromhex(
            "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
        )
    )

    """
    The first input comes from an ordinary P2PK:
        scriptPubKey : 2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac value: 6.25
        private key  : bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866
    
    The second input comes from a P2WPKH witness program:
        scriptPubKey : 00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1, value: 6
        private key  : 619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9
        public key   : 025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357
    """

    input_2_scriptpubkey = bytes.fromhex(
        "00"  # witness version
        + "14"  # OP_PUSHDATA20
        + "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1"  # witness program
    )
    input_2_witness_program = input_2_scriptpubkey[2:]
    scriptcode = bits.script.script(
        [
            bits.script.script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    input_2_witness_program.hex(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ],
            ).hex()
        ]
    )
    preimage = bits.script.v0_witness_preimage(
        unsigned_tx,
        1,
        int(6 * constants.COIN),
        scriptcode,
        constants.SIGHASH_ALL,
    )

    expected_preimage = bytes.fromhex(
        "0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000"
    )
    assert preimage.hex() == expected_preimage.hex(), "preimage mismatch"

    sighash = bits.crypto.hash256(preimage)
    expected_sighash = bytes.fromhex(
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    )
    assert sighash.hex() == expected_sighash.hex(), "sighash data mismatch"

    # sign for tx input 0 P2PK
    input_1_scriptpubkey = bytes.fromhex(
        "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"
    )
    input_1_private_key = bytes.fromhex(
        "bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866"
    )
    txins = [
        bits.tx.txin(
            unsigned_tx["txins"][0]["outpoint"],
            input_1_scriptpubkey,  # re-serialize with outpoint's scriptpubkey as scriptsig
            sequence=unsigned_tx["txins"][0]["sequence"].to_bytes(4, "little"),
        ),
        unsigned_tx["txins"][1],
    ]
    tx_ = bits.tx.tx(
        txins,
        unsigned_tx["txouts"],
        version=unsigned_tx["version"],
        locktime=unsigned_tx["locktime"],
    )

    input_1_signature = bits.script.sig(
        input_1_private_key,
        tx_,
        sighash_flag=constants.SIGHASH_ALL,
    )
    input_1_scriptsig = bits.script.p2pk_script_sig(input_1_signature)
    txins = [
        bits.tx.txin(
            unsigned_tx["txins"][0]["outpoint"],
            input_1_scriptsig,  # re-serialize now with scriptsig
            sequence=unsigned_tx["txins"][0]["sequence"].to_bytes(4, "little"),
        ),
        unsigned_tx["txins"][1],
    ]

    # sign for tx input 1 P2WPKH
    input_2_private_key = bytes.fromhex(
        "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"
    )
    witness_signature = bits.script.sig(
        input_2_private_key, preimage, msg_preimage=True
    )

    input_2_pubkey = bytes.fromhex(
        "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
    )
    input_2_witness_script = bits.script.script(
        [
            witness_signature.hex(),
            input_2_pubkey.hex(),
        ],
        witness=True,
    )
    signed_tx = bits.tx.tx(
        txins,
        unsigned_tx["txouts"],
        version=unsigned_tx["version"],
        locktime=unsigned_tx["locktime"],
        script_witnesses=[
            bits.script.script([], witness=True),
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
    assert (
        signed_tx.hex() == expected_signed_transaction.hex()
    ), "tx does not match expected signed transaction"


def test_p2sh_p2wpkh():
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
    unsigned_tx = Tx(
        bytes.fromhex(
            "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
        )
    )
    """
    The input comes from a P2SH-P2WPKH witness program:
        scriptPubKey : a9144733f37cf4db86fbc2efed2500b4f4e49f31202387, value: 10
        redeemScript : 001479091972186c449eb1ded22b78e40d009bdf0089
        private key  : eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf
        public key   : 03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873
    """
    txin_index = 0
    txin_value = int(10e8)
    txin_scriptpubkey = bytes.fromhex("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387")
    txin_redeem_script = bytes.fromhex(
        "00"  # witness v0
        + "14"  # length of witness program = 20 => p2wpkh
        + "79091972186c449eb1ded22b78e40d009bdf0089"
    )
    txin_witness_program = txin_redeem_script[2:]
    scriptcode = bits.script.script(
        [
            bits.script.script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    txin_witness_program.hex(),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ).hex()
        ]
    )

    txin_pubkey = bytes.fromhex(
        "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
    )

    txins = [
        bits.tx.txin(
            unsigned_tx["txins"][txin_index]["outpoint"],
            bits.script.script([txin_redeem_script.hex()]),
            sequence=unsigned_tx["txins"][txin_index]["sequence"].to_bytes(4, "little"),
        )
    ]
    tx_ = Tx(
        bits.tx.tx(
            txins,
            unsigned_tx["txouts"],
            version=unsigned_tx["version"],
            locktime=unsigned_tx["locktime"],
        )
    )
    preimage = bits.script.v0_witness_preimage(
        tx_,
        txin_index,
        txin_value,
        scriptcode,
        constants.SIGHASH_ALL,
    )
    expected_preimage = bytes.fromhex(
        "01000000b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001976a91479091972186c449eb1ded22b78e40d009bdf008988ac00ca9a3b00000000feffffffde984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c839204000001000000"
    )
    assert (
        preimage.hex() == expected_preimage.hex()
    ), "mismatch for expected hash preimage"

    sighash = bits.crypto.hash256(preimage)
    expected_sighash = bytes.fromhex(
        "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
    )
    assert sighash.hex() == expected_sighash.hex(), "mismatch for expected sighash"

    private_key = bytes.fromhex(
        "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf"
    )
    signature = bits.script.sig(private_key, preimage, msg_preimage=True)
    signed_tx = bits.tx.tx(
        txins,
        unsigned_tx["txouts"],
        version=unsigned_tx["version"],
        locktime=unsigned_tx["locktime"],
        script_witnesses=[
            bits.script.script([signature.hex(), txin_pubkey.hex()], witness=True)
        ],
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
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh
    unsigned_tx = Tx(
        bytes.fromhex(
            "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000"
        )
    )

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
    input_0_value = int(1.5625 * constants.COIN)
    input_0_private_key = bytes.fromhex(
        "b8f28a772fccbf9b4f58a4f027e07dc2e35e7cd80529975e292ea34f84c4580c"
    )
    input_0_sig = bytes.fromhex(
        "304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201"
    )

    # second input, P2WSH, the one we are signing for
    txin_index = 1
    txin_value = int(49 * constants.COIN)
    txin_scriptpubkey = bytes.fromhex(
        "00"  # witness v0
        + "20"  # length of witness program = 32 => p2wsh
        + "5d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"
    )
    txin_witness_script = bytes.fromhex(
        "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
    )
    scriptcode = bits.script.script([txin_witness_script.hex()])
    decoded_witness_script = bits.script.decode_script(txin_witness_script)
    # decoded_witness_script = [
    #    "026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae",
    #    "OP_CHECKSIGVERIFY",
    #    "OP_CODESEPARATOR",
    #    "0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465",
    #    "OP_CHECKSIG"
    # ]
    txins = [
        bits.tx.txin(
            unsigned_tx["txins"][0]["outpoint"],
            bits.script.script([input_0_sig.hex()]),
            sequence=unsigned_tx["txins"][0]["sequence"].to_bytes(4, "little"),
        ),
        bits.tx.txin(
            unsigned_tx["txins"][1]["outpoint"],
            b"",
            sequence=unsigned_tx["txins"][1]["sequence"].to_bytes(4, "little"),
        ),
    ]
    tx_ = Tx(
        bits.tx.tx(
            txins,
            unsigned_tx["txouts"],
            version=unsigned_tx["version"],
            locktime=unsigned_tx["locktime"],
        )
    )
    preimage = bits.script.v0_witness_preimage(
        tx_,
        txin_index,
        txin_value,
        scriptcode,
        constants.SIGHASH_SINGLE,
    )
    expected_preimage = bytes.fromhex(
        "01000000ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d4100000000000000000000000000000000000000000000000000000000000000000815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f8000000004721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac0011102401000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000003000000"
    )
    assert preimage.hex() == expected_preimage.hex(), "preimage mismatch"

    sighash = bits.crypto.hash256(preimage)
    expected_sighash = bytes.fromhex(
        "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391"
    )
    assert sighash.hex() == expected_sighash.hex(), "mismatch for expected sighash"

    # 026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae private key
    private_key_1 = bytes.fromhex(
        "8e02b539b1500aa7c81cf3fed177448a546f19d2be416c0c61ff28e577d8d0cd"
    )
    signature_1 = bits.script.sig(private_key_1, preimage, msg_preimage=True)

    decoded_witness_script = decoded_witness_script[
        decoded_witness_script.index("OP_CODESEPARATOR") + 1 :
    ]
    txin_witness_script_prime = bits.script.script(decoded_witness_script)
    scriptcode = bits.script.script([txin_witness_script_prime.hex()])
    preimage = bits.script.v0_witness_preimage(
        tx_,
        txin_index,
        txin_value,
        scriptcode,
        constants.SIGHASH_SINGLE,
    )
    expected_preimage = bytes.fromhex(
        "01000000ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d4100000000000000000000000000000000000000000000000000000000000000000815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000023210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac0011102401000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000003000000"
    )
    assert (
        preimage.hex() == expected_preimage.hex()
    ), "mismatch for expected pre-image post-op-codeseparator"

    sighash = bits.crypto.hash256(preimage)
    expected_sighash = bytes.fromhex(
        "fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47"
    )
    assert (
        sighash.hex() == expected_sighash.hex()
    ), "mismatch for expected sighash post-op-codeseparator"

    # 0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465 private key
    private_key_2 = bytes.fromhex(
        "86bf2ed75935a0cbef03b89d72034bb4c189d381037a5ac121a70016db8896ec"
    )
    signature_2 = bits.script.sig(
        private_key_2,
        preimage,
        sighash_flag=constants.SIGHASH_SINGLE,
        msg_preimage=True,
    )
    signed_tx = bits.tx.tx(
        txins,
        unsigned_tx["txouts"],
        version=unsigned_tx["version"],
        locktime=unsigned_tx["locktime"],
        script_witnesses=[
            bits.script.script([], witness=True),
            bits.script.script(
                [signature_2.hex(), signature_1.hex(), txin_witness_script.hex()],
                witness=True,
            ),
        ],
    )
    # signed_tx differs slightly from expected in BIP since signatures are different
    # i suppose this is because signatures are non-deterministic?
    # so we insert the signatures we derived below
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
        signed_tx.hex() == expected_signed_tx.hex()
    ), "mismatch for expected signed transaction"


def test_p2wsh_2():
    # Second example from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh
    # "This example shows how unexecuted OP_CODESEPARATOR is processed, and SINGLE|ANYONECANPAY does not commit to the input index"
    unsigned_tx = Tx(
        bytes.fromhex(
            "0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000"
        )
    )

    """
    The first input comes from a native P2WSH witness program:
        scriptPubKey: 0020ba468eea561b26301e4cf69fa34bde4ad60c81e70f059f045ca9a79931004a4d value: 0.16777215
        witnessScript:0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
                        0 IF CODESEPARATOR ENDIF <0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98> CHECKSIG

    The second input comes from a native P2WSH witness program:
        scriptPubKey: 0020d9bbfbe56af7c4b7f960a70d7ea107156913d9e5a26b0a71429df5e097ca6537 value: 0.16777215
        witnessScript:5163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
                        1 IF CODESEPARATOR ENDIF <0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98> CHECKSIG
    """

    txin_0_witness_script = bytes.fromhex(
        "0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"
    )
    decoded_txin_0_witness_script = bits.script.decode_script(txin_0_witness_script)
    # ['OP_FALSE',
    #  'OP_IF',
    #  'OP_CODESEPARATOR',
    #  'OP_ENDIF',
    #  '0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98',
    #  'OP_CHECKSIG']
    scriptcode = bits.script.script([txin_0_witness_script.hex()])
    preimage = bits.script.v0_witness_preimage(
        unsigned_tx,
        0,
        int(0.16777215 * constants.COIN),
        scriptcode,
        constants.SIGHASH_SINGLE | constants.SIGHASH_ANYONECANPAY,
    )
    expected_preimage = bytes.fromhex(
        "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc00100000000270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98acffffff0000000000ffffffffb258eaf08c39fbe9fbac97c15c7e7adeb8df142b0df6f83e017f349c2b6fe3d20000000083000000"
    )
    assert (
        preimage.hex() == expected_preimage.hex()
    ), "mismatch for expected pre-image - 1st txin"
    sighash = bits.crypto.hash256(preimage)
    expected_sighash = bytes.fromhex(
        "e9071e75e25b8a1e298a72f0d2e9f4f95a0f5cdf86a533cda597eb402ed13b3a"
    )
    assert (
        sighash.hex() == expected_sighash.hex()
    ), "mismatch for expected sighash - 1st txin"
    txin_0_private_key = bytes.fromhex(
        "f52b3484edd96598e02a9c89c4492e9c1e2031f471c49fd721fe68b3ce37780d"
    )
    signature_0 = bits.script.sig(txin_0_private_key, preimage, msg_preimage=True)

    decoded_txin_0_witness_script = decoded_txin_0_witness_script[
        decoded_txin_0_witness_script.index("OP_CODESEPARATOR") + 1 :
    ]
    txin_0_witness_script_prime = bits.script.script(decoded_txin_0_witness_script)
    scriptcode = bits.script.script([txin_0_witness_script_prime.hex()])

    txin_1_witness_script = bytes.fromhex(
        "5163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"
    )
    decoded_txin_1_witness_script = bits.script.decode_script(txin_1_witness_script)
    decoded_txin_1_witness_script_prime = decoded_txin_1_witness_script[
        decoded_txin_1_witness_script.index("OP_CODESEPARATOR") + 1 :
    ]
    scriptcode = bits.script.script(
        [bits.script.script(decoded_txin_1_witness_script_prime).hex()]
    )
    # should scriptcode come from txin1 witness script after codeseparator? 🤷‍♂️
    # in this example actually makes no difference

    preimage = bits.script.v0_witness_preimage(
        unsigned_tx,
        1,
        int(0.16777215 * constants.COIN),
        scriptcode,
        constants.SIGHASH_SINGLE | constants.SIGHASH_ANYONECANPAY,
    )
    expected_preimage = bytes.fromhex(
        "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b000000002468210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98acffffff0000000000ffffffff91ea93dd77f702b738ebdbf3048940a98310e869a7bb8fa2c6cb3312916947ca0000000083000000"
    )
    assert (
        preimage.hex() == expected_preimage.hex()
    ), "mismatch for expected pre-image - 2nd txin"
    expected_sighash = bytes.fromhex(
        "cd72f1f1a433ee9df816857fad88d8ebd97e09a75cd481583eb841c330275e54"
    )
    sighash = bits.crypto.hash256(preimage)
    assert (
        sighash.hex() == expected_sighash.hex()
    ), "mismatch for expected sighash - 2nd txin"
    signature_1 = bits.script.sig(
        txin_0_private_key, preimage, msg_preimage=True
    )  # uses same private key
    signed_tx = bits.tx.tx(
        unsigned_tx["txins"],
        unsigned_tx["txouts"],
        script_witnesses=[
            bits.script.script(
                [signature_0.hex(), txin_0_witness_script.hex()], witness=True
            ),
            bits.script.script(
                [signature_1.hex(), txin_1_witness_script.hex()], witness=True
            ),
        ],
        version=unsigned_tx["version"],
        locktime=unsigned_tx["locktime"],
    )
    expected_signed_tx = bytes.fromhex(
        "01000000"
        + "00"
        + "01"
        + "02"
        + "e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc001"
        + "00000000"
        + "00"
        + "ffffffff"
        + "80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b"
        + "00000000"
        + "00"
        + "ffffffff"
        + "02"
        + "8096980000000000"
        + "1976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac"
        + "8096980000000000"
        + "1976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac"
        + "02"
        + format(len(signature_0), "02x")
        + signature_0.hex()
        + "27"
        + "0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"
        + "02"
        + format(len(signature_1), "02x")
        + signature_1.hex()
        + "27"
        + "5163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"
        + "00000000"
    )
    assert (
        signed_tx.hex() == expected_signed_tx.hex()
    ), "mismatch for expected signed transaction"
    # "Since SINGLE|ANYONECANPAY does not commit to the input index, the signatures are still valid when the input-output pairs are swapped"


def test_p2sh_p2wsh():
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wsh
    # 6 of 6 multisig
    unsigned_tx = Tx(
        bytes.fromhex(
            "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000"
        )
    )

    """
    The input comes from a P2SH-P2WSH 6-of-6 multisig witness program:
        scriptPubKey : a9149993a429037b5d912407a71c252019287b8d27a587, value: 9.87654321
        redeemScript : 0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54
        witnessScript: 56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    """
    txin_0_redeem_script = bytes.fromhex(
        "0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54"
    )
    txins = [
        bits.tx.txin(
            unsigned_tx["txins"][0]["outpoint"],
            bits.script.script([txin_0_redeem_script.hex()]),
        )
    ]
    tx_ = Tx(
        bits.tx.tx(
            txins,
            unsigned_tx["txouts"],
            version=unsigned_tx["version"],
            locktime=unsigned_tx["locktime"],
        )
    )
    txin_0_witness_script = bytes.fromhex(
        "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"
    )
    decoded_txin_0_witness_script = bits.script.decode_script(txin_0_witness_script)
    # decoded_txin_0_witness_script = [
    #     "OP_6",
    #     "0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3",
    #     "03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b",
    #     "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a",
    #     "033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f4",
    #     "03a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac16",
    #     "02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b",
    #     "OP_6",
    #     "OP_CHECKMULTISIG",
    # ]
    scriptcode = len(txin_0_witness_script).to_bytes(1, "big") + txin_0_witness_script
    # ^ i suppose it's not serialized like script() with OP_PUSHDATA1 ?
    signatures = []
    for sh_flag, expected_preimage, expected_sighash, private_key in [
        (
            constants.SIGHASH_ALL,
            bytes.fromhex(
                "0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa03bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e7066504436641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffffbc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc0000000001000000"
            ),
            bytes.fromhex(
                "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c"
            ),
            bytes.fromhex(
                "730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6"
            ),
        ),
        (
            constants.SIGHASH_NONE,
            bytes.fromhex(
                "0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000002000000"
            ),
            bytes.fromhex(
                "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36"
            ),
            bytes.fromhex(
                "11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3"
            ),
        ),
        (
            constants.SIGHASH_SINGLE,
            bytes.fromhex(
                "0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f7080000000003000000"
            ),
            bytes.fromhex(
                "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea"
            ),
            bytes.fromhex(
                "77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661"
            ),
        ),
        (
            constants.SIGHASH_ALL | constants.SIGHASH_ANYONECANPAY,
            bytes.fromhex(
                "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffffbc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc0000000081000000"
            ),
            bytes.fromhex(
                "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e"
            ),
            bytes.fromhex(
                "14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49"
            ),
        ),
        (
            constants.SIGHASH_NONE | constants.SIGHASH_ANYONECANPAY,
            bytes.fromhex(
                "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000082000000"
            ),
            bytes.fromhex(
                "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a"
            ),
            bytes.fromhex(
                "fe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323"
            ),
        ),
        (
            constants.SIGHASH_SINGLE | constants.SIGHASH_ANYONECANPAY,
            bytes.fromhex(
                "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f7080000000083000000"
            ),
            bytes.fromhex(
                "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b"
            ),
            bytes.fromhex(
                "428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890"
            ),
        ),
    ]:
        preimage = bits.script.v0_witness_preimage(
            tx_,
            0,
            int(9.87654321 * constants.COIN),
            scriptcode,
            sh_flag,
        )
        assert (
            preimage.hex() == expected_preimage.hex()
        ), f"mismatch for preimage - sighash flag {format(sh_flag, '02x')}"
        assert (
            bits.crypto.hash256(preimage).hex() == expected_sighash.hex()
        ), f"mismatch for sighash - sighash flag {format(sh_flag, '02x')}"
        signature = bits.script.sig(
            private_key, preimage, sighash_flag=sh_flag, msg_preimage=True
        )
        signatures.append(signature)

    signed_tx = bits.tx.tx(
        txins,
        unsigned_tx["txouts"],
        script_witnesses=[
            bits.script.script(
                ["OP_0"]
                + [sig_.hex() for sig_ in signatures]
                + [txin_0_witness_script.hex()],
                witness=True,
            )
            # + len(txin_0_witness_script).to_bytes(1, "big")
            # + txin_0_witness_script
            # ^^ i suppose witness script not serialized same as normal script
            # regarding OP_PUSHDATA1
            # does that imply max data push is 0xff ?
        ],
        version=unsigned_tx["version"],
        locktime=unsigned_tx["locktime"],
    )
    expected_signed_tx = bytes.fromhex(
        "01000000"
        + "00"
        + "01"
        + "01"
        + "36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e"
        + "01000000"
        + "23"
        + "220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54"
        + "ffffffff"
        + "02"
        + "00e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688ac"
        + "c0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac"
        + "08"
        + "00"
        + "".join([format(len(sig_), "02x") + sig_.hex() for sig_ in signatures])
        + "cf"
        + "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"
        + "00000000"
    )
    assert (
        signed_tx.hex() == expected_signed_tx.hex()
    ), "mismatch for expected signed transaction"


def test_no_find_and_delete():
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#no-findanddelete
    unsigned_tx = Tx(
        bytes.fromhex(
            "010000000169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f14c1d000000ffffffff0101000000000000000000000000"
        )
    )

    """
    The input comes from a P2WSH witness program:
        scriptPubKey : 00209e1be07558ea5cc8e02ed1d80c0911048afad949affa36d5c3951e3159dbea19, value: 200000
        redeemScript : OP_CHECKSIGVERIFY <0x30450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01>
                        ad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01
    """

    txin_0_redeem_script = bytes.fromhex(
        "ad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01"
    )
    decoded_txin_0_redeem_script = bits.script.decode_script(txin_0_redeem_script)
    signature = bytes.fromhex(decoded_txin_0_redeem_script[-1])

    scriptcode = bits.script.script([txin_0_redeem_script.hex()])
    preimage = bits.script.v0_witness_preimage(
        unsigned_tx,
        0,
        int(0.002 * constants.COIN),
        scriptcode,
        constants.SIGHASH_ALL,
    )
    expected_preimage = bytes.fromhex(
        "01000000b67c76d200c6ce72962d919dc107884b9d5d0e26f2aea7474b46a1904c53359f3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e7066504469c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f14c1d00004aad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01400d030000000000ffffffffe5d196bfb21caca9dbd654cafb3b4dc0c4882c8927d2eb300d9539dd0b9342280000000001000000"
    )
    assert preimage.hex() == expected_preimage.hex(), "mismatch for pre-image"
    expected_sighash = bytes.fromhex(
        "71c9cd9b2869b9c70b01b1f0360c148f42dee72297db312638df136f43311f23"
    )
    assert (
        bits.crypto.hash256(preimage).hex() == expected_sighash.hex()
    ), "mismatch for sighash"

    # # pubkey recovery
    # pubkey_ = bits.keys.pub(bits.keys.key(), compressed=True)
    # while not bits.script.sig_verify(signature, pubkey_, expected_sighash, msg_preimage=True):
    #     pubkey_ = bits.keys.pub(bits.keys.key(), compressed=True)
    pubkey_ = bytes.fromhex(
        "02a9781d66b61fb5a7ef00ac5ad5bc6ffc78be7b44a566e3c87870e1079368df4c"
    )
    assert bits.script.sig_verify(
        signature, pubkey_, bits.crypto.hash256(preimage), msg_preimage=True
    ), "signature verification for recovered pubkey failed"

    signed_tx = bits.tx.tx(
        unsigned_tx["txins"],
        unsigned_tx["txouts"],
        script_witnesses=[
            bits.script.script(
                [signature.hex(), pubkey_.hex(), txin_0_redeem_script.hex()],
                witness=True,
            )
        ],
        version=unsigned_tx["version"],
        locktime=unsigned_tx["locktime"],
    )
    expected_signed_tx = bytes.fromhex(
        "0100000000010169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f14c1d000000ffffffff01010000000000000000034830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e012102a9781d66b61fb5a7ef00ac5ad5bc6ffc78be7b44a566e3c87870e1079368df4c4aad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0100000000"
    )
    assert (
        signed_tx.hex() == expected_signed_tx.hex()
    ), "mismatch for signed transaction"
