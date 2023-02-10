"""
https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
"""
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

bech32_max_len = 90
bech32_chars = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l"
bech32_int_map = {b.to_bytes(1, "big"): bech32_chars.index(b) for b in bech32_chars}
bech32_separator = b"1"


def parse_bech32(bytestring: bytes) -> Tuple[bytes]:
    """
    Parse bech32 to (hrp, data)
    """
    assert len(bytestring) <= bech32_max_len, "overall max length exceeded"
    assert bytestring.isupper() or bytestring.islower(), "mixed case string"
    bytestring = bytestring.lower()
    assert bech32_separator in bytestring, "No separator character"
    string_split = bytestring.split(bech32_separator)
    hrp = bech32_separator.join(string_split[:-1])
    assert hrp, "Empty HRP"
    data = string_split[-1]
    return hrp, data


def assert_valid_bech32(hrp: bytes, data: bytes) -> bool:
    """
    Test for valid bech32 format and checksum
    """
    for char in hrp:
        assert int(char) in range(33, 127), "HRP character out of range"
    assert len(hrp) in range(1, 84), "human readable part length not in [1,83]"

    checksum = data[-6:]
    assert len(checksum) == 6, "Too short checksum"
    for char in checksum:
        assert char.to_bytes(1, "big") in bech32_chars, "Invalid character in checksum"

    for char in data:
        assert char in bech32_chars, "Invalid data character"

    assert bech32_verify_checksum(
        [char.to_bytes(1, "big") for char in hrp],
        [bech32_int_map[char.to_bytes(1, "big")] for char in data],
    ), "invalid checksum"


def bech32_encode(
    hrp: bytes, data: bytes, witness_version: Optional[bytes] = b""
) -> bytes:
    """
    https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#bech32
    Args:
        hrp: bytes, human readable part
        data: bytes, data
        witness_version: Optional[bytes], witness version to be prepended to data part
    """
    assert len(hrp) in range(1, 84), "human readable part length not in [1,83]"
    for char in hrp:
        assert int(char) in range(33, 127), "char in hrp not ascii value in [33, 126]"
    assert len(data) in range(
        6, bech32_max_len - len(hrp) - len(bech32_separator) - len(witness_version) + 1
    ), "addr data exceeds MAX_LEN"

    encoded = b""
    data_int = int.from_bytes(data, "big")
    data_len = len(data)

    groups_of_5 = data_len * 8 // 5
    if modulo := data_len * 8 % 5:
        groups_of_5 += 1
        data_int <<= 5 - modulo

    for i in range(groups_of_5):
        group_val = (data_int >> 5 * (groups_of_5 - i - 1)) & 0x1F
        encoded += bech32_chars[group_val : group_val + 1]

    # calculate checksum
    data_part = witness_version + encoded
    checksum = bech32_create_checksum(
        [h.to_bytes(1, "big") for h in hrp],
        [bech32_int_map[d.to_bytes(1, "big")] for d in data_part],
    )
    checksum = b"".join([bech32_chars[c : c + 1] for c in checksum])

    return hrp + bech32_separator + witness_version + encoded + checksum


def segwit_addr(
    data: bytes, witness_version: int = 0, network: str = "mainnet"
) -> bytes:
    # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#segwit-address-format
    if network == "mainnet":
        hrp = b"bc"
    elif network == "testnet":
        hrp = b"tb"
    else:
        raise ValueError(f"unrecognized network: {network}")
    assert witness_version in range(17), "witness version not in [0, 16]"
    return bech32_encode(
        hrp, data, witness_version=bech32_chars[witness_version : witness_version + 1]
    )


def bech32_decode(data: bytes) -> bytes:
    """
    Decode bech32
    """
    # decode into 5-bit integers
    integers = []
    for d in data:
        d = d.to_bytes(1, "big")  # translate back to byte value
        integers.append(bech32_int_map[d])

    # rearrange into 8-bit groups
    decoded_bits = 5 * len(integers)
    decoded = integers[0]
    for integer in integers[1:]:
        decoded <<= 5
        decoded |= integer
    if modulo := decoded_bits % 8:
        # discard zero-padding
        assert (
            bin(decoded)[-modulo:] == "0" * modulo
        ), "non-zero padding in 8-to-5 conversion"
        assert modulo <= 4, "zero padding of more than 4 bits"
        decoded >>= modulo
        decoded_bits -= modulo
    return decoded.to_bytes(decoded_bits // 8, "big")


def decode_segwit_addr(addr: bytes) -> tuple[bytes, int, bytes]:
    hrp, data = parse_bech32(addr)
    assert_valid_bech32(hrp, data)
    data = data[:-6]  # discard checksum
    assert data, "empty data"
    witness_version = bech32_int_map[data[0:1]]
    assert witness_version in range(17), "witness version not in [0, 16]"

    data = data[1:]
    witness_program = bech32_decode(data)

    return hrp, witness_version, witness_program


def assert_valid_segwit(
    hrp: bytes, witness_version: int, witness_program: bytes
) -> bool:
    assert hrp in [b"bc", b"tb"], "Invalid human-readable part"
    assert len(witness_program) in range(2, 41), "witness program length not in [2, 40]"
    if witness_version == 0:
        # why is 20 allowed?
        assert len(witness_program) in [
            20,
            32,
        ], "length of v0 witness program not 20 or 32"


# added type hints and docstring to
## https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#checksum
def bech32_polymod(values: List[int]) -> int:
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(s: List[Union[str, bytes]]) -> List[int]:
    return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]


def bech32_verify_checksum(hrp: List[Union[str, bytes]], data: List[int]) -> bool:
    """
    Args:
        data: List[int], data part values including checksum
    """
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp: List[Union[str, bytes]], data: List[int]) -> List[int]:
    """
    Args:
        data: List[int], (non-checksum) data part values
    """
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
