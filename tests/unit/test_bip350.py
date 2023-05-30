import pytest

import bits
from bits.bips import bip173
from bits.bips.bip350 import BECH32M_CONST


@pytest.mark.parametrize(
    "bytestring",
    (
        b"A1LQFN3A",
        b"a1lqfn3a",
        b"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        b"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        b"11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
        b"split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        b"?1v759aa",
    ),
)
def test_valid_bech32m(bytestring):
    # "No string can be simultaneously valid Bech32 and Bech32m, so the above examples
    # also serve as invalid test vectors for Bech32."
    hrp, data = bip173.parse_bech32(bytestring)
    bip173.assert_valid_bech32(hrp, data, constant=BECH32M_CONST)


@pytest.mark.parametrize(
    "bytestring,reason",
    (
        (b"\x201xj0phk", "HRP character out of range"),
        (b"\x7F1g6xzxy", "HRP character out of range"),
        (b"\x801vctc34", "HRP character out of range"),
        (
            b"an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
            "overall max length exceeded",
        ),
        (b"qyrz8wqd2c9m", "No separator character"),
        (b"1qyrz8wqd2c9m", "Empty HRP"),
        (b"y1b0jsk6g", "Invalid data character"),
        (b"lt1igcx5c0", "Invalid data character"),
        (b"in1muywd", "Too short checksum"),
        (b"mm1crxm3i", "Invalid character in checksum"),
        (b"au1s5cgom", "Invalid character in checksum"),
        (
            b"M1VUXWEZ",
            "invalid checksum",
        ),  # checksum calculated with uppercase form of HRP
        (b"16plkw9", "Empty HRP"),
        (b"1p2gdwpf", "Empty HRP"),
    ),
)
def test_invalid_bech32m(bytestring, reason):
    try:
        hrp, data = bip173.parse_bech32(bytestring)
        bip173.assert_valid_bech32(hrp, data, constant=BECH32M_CONST)
        assert False, "valid bech32m"
    except AssertionError as err:
        assert err.args[0] == reason


@pytest.mark.parametrize(
    "segwit_addr,expected_script_pubkey",
    (
        (
            b"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        (
            b"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ),
        (
            b"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
            "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        (b"BC1SW50QGDZ25J", "6002751e"),
        (
            b"bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
            "5210751e76e8199196d454941c45d1b3a323",
        ),
        (
            b"tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
        (
            b"tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
        (
            b"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
    ),
)
def test_segwit_script_pubkey(segwit_addr, expected_script_pubkey):
    hrp, witness_version, witness_program = bits.decode_segwit_addr(segwit_addr)
    assert (
        bits.script.p2wpkh_script_pubkey(
            witness_program, witness_version=witness_version
        ).hex()
        == expected_script_pubkey
    )


@pytest.mark.parametrize(
    "segwit_addr,reason",
    (
        (
            b"tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            "Invalid human-readable part",
        ),
        (
            b"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            "invalid checksum",
        ),
        (
            b"tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
            "invalid checksum",  # Bech32 instead of Bech32m
        ),
        (
            b"BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
            "invalid checksum",  # Bech32 instead of Bech32m
        ),
        (
            b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            "invalid checksum",  # Bech32m instead of Bech32)
        ),
        (
            b"tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
            "invalid checksum",  # Bech32m instead of Bech32
        ),
        (
            b"bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
            "Invalid character in checksum",
        ),
        (
            b"BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
            "witness version not in [0, 16]",
        ),
        (b"bc1pw5dgrnzv", "witness program length not in [2, 40]"),  # 1 byte
        (
            b"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
            "witness program length not in [2, 40]",  # 41 byes
        ),
        (
            b"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "length of v0 witness program not 20 or 32",
            # Invalid v0 witness program length (per BIP141)
        ),
        (
            b"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
            "mixed case string",
        ),
        (
            b"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            "zero padding of more than 4 bits",
        ),
        (
            b"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
            "non-zero padding in 8-to-5 conversion",
        ),
        (b"bc1gmk9yu", "empty data"),
    ),
)
def test_invalid_segwit_addr(segwit_addr, reason):
    try:
        hrp, witness_version, witness_program = bits.decode_segwit_addr(segwit_addr)
        bits.assert_valid_segwit(hrp, witness_version, witness_program)
    except AssertionError as err:
        assert err.args[0] == reason
