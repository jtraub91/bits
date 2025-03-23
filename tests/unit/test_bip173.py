import pytest

import bits.constants
import bits.crypto
import bits.script
from bits.bips import bip173


@pytest.mark.parametrize(
    "expected_addr,network",
    (
        (b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "mainnet"),
        (b"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet"),
    ),
)
def test_example_p2wpkh(expected_addr, network):
    pubkey = bytes.fromhex(
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    )
    pkh = bits.pubkey_hash(pubkey)
    assert bits.segwit_addr(pkh, network=network) == expected_addr


@pytest.mark.parametrize(
    "expected_addr,network",
    [
        (b"bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "mainnet"),
        (b"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "testnet"),
    ],
)
def test_example_p2wsh(expected_addr, network):
    pubkey = bytes.fromhex(
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    )
    redeem_script = (
        len(pubkey).to_bytes(1, "big")
        + pubkey
        + bits.constants.OP_CHECKSIG.to_bytes(1, "big")
    )
    sh = bits.crypto.sha256(redeem_script)
    assert bits.segwit_addr(sh, network=network) == expected_addr


@pytest.mark.parametrize(
    "bytestring",
    (
        b"A12UEL5L",
        b"a12uel5l",
        b"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        b"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        b"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        b"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        b"?1ezyfcl",
    ),
)
def test_valid_bech32(bytestring):
    hrp, data = bip173.parse_bech32(bytestring)
    bip173.assert_valid_bech32(hrp, data)


@pytest.mark.parametrize(
    "bytestring,reason",
    (
        (b"\x201nwldj5", "HRP character out of range"),
        (b"\x7F1axkwrx", "HRP character out of range"),
        (b"\x801eym55h", "HRP character out of range"),
        (
            b"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
            "overall max length exceeded",
        ),
        (b"pzry9x0s0muk", "No separator character"),
        (b"1pzry9x0s0muk", "Empty HRP"),
        (b"x1b4n0q5v", "Invalid data character"),
        (b"li1dgmt3", "Too short checksum"),
        (b"de1lg7wt\xff", "Invalid character in checksum"),
        (
            b"A1G7SGD8",
            "invalid checksum",
        ),  # checksum calculated with uppercase form of HRP
        (b"10a06t8", "Empty HRP"),
        (b"1qzzfhee", "Empty HRP"),
    ),
)
def test_invalid_bech32(bytestring, reason):
    try:
        hrp, data = bip173.parse_bech32(bytestring)
        bip173.assert_valid_bech32(hrp, data)
        assert False, "valid bech32"
    except AssertionError as err:
        assert err.args[0] == reason


@pytest.mark.parametrize(
    "segwit_addr,expected_script_pubkey",
    [
        (
            b"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        (
            b"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ),
        (
            b"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
            "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        (b"BC1SW50QA3JX3S", "6002751e"),
        (
            b"bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
            "5210751e76e8199196d454941c45d1b3a323",
        ),
        (
            b"tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
    ],
)
def test_segwit_script_pubkey(segwit_addr, expected_script_pubkey):
    hrp, witness_version, witness_program = bits.decode_segwit_addr(
        segwit_addr, __support_bip350=False
    )
    assert (
        bits.script.p2wpkh_script_pubkey(
            witness_program, witness_version=witness_version
        ).hex()
        == expected_script_pubkey
    )


@pytest.mark.parametrize(
    "segwit_addr,reason",
    [
        (b"tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", "Invalid human-readable part"),
        (b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "invalid checksum"),
        (
            b"BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            "witness version not in [0, 16]",
        ),
        (b"bc1rw5uspcuh", "witness program length not in [2, 40]"),
        (
            b"bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "witness program length not in [2, 40]",
        ),
        (
            b"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "length of v0 witness program not 20 or 32",
        ),
        (
            b"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            "mixed case string",
        ),
        (b"bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", "zero padding of more than 4 bits"),
        (
            b"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            "non-zero padding in 8-to-5 conversion",
        ),
        (b"bc1gmk9yu", "empty data"),
    ],
)
def test_invalid_segwit_addr(segwit_addr, reason):
    try:
        hrp, witness_version, witness_program = bits.decode_segwit_addr(
            segwit_addr, __support_bip350=False
        )
        bits.assert_valid_segwit(hrp, witness_version, witness_program)
    except AssertionError as err:
        assert err.args[0] == reason
