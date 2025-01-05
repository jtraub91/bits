# Copyright (c) 2023 Jason Traub
# Distributed under the MIT License, see LICENSE.txt for details
"""
https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
"""
import typing

bech32_max_len = 90
bech32_chars = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l"
bech32_int_map = {b.to_bytes(1, "big"): bech32_chars.index(b) for b in bech32_chars}
bech32_separator = b"1"

hrp_network_map = {b"bc": "mainnet", b"tb": "testnet", b"bcrt": "regtest"}


def parse_bech32(bytestring: bytes) -> typing.Tuple[bytes]:
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


def assert_valid_bech32(hrp: bytes, data: bytes, constant: int = 1) -> bool:
    """
    Test for valid bech32(m) format and checksum
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
        constant=constant,
    ), "invalid checksum"


def bech32_encode(
    hrp: bytes,
    data: bytes,
    witness_version: typing.Optional[bytes] = b"",
    constant: int = 1,
) -> bytes:
    """
    https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#bech32
    Args:
        hrp: bytes, human readable part
        data: bytes, data
        witness_version: Optional[bytes], witness version to be prepended to data part
        constant: int, 1 for bech32 0x2bc830a3 for bech32m per BIP350
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
    modulo = data_len * 8 % 5
    if modulo:
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
        constant=constant,
    )
    checksum = b"".join([bech32_chars[c : c + 1] for c in checksum])

    return hrp + bech32_separator + witness_version + encoded + checksum


def bech32_decode(data: bytes) -> bytes:
    """
    Decode bech32 data part
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
    modulo = decoded_bits % 8
    if modulo:
        # discard zero-padding
        assert (
            bin(decoded)[-modulo:] == "0" * modulo
        ), "non-zero padding in 8-to-5 conversion"
        assert modulo <= 4, "zero padding of more than 4 bits"
        decoded >>= modulo
        decoded_bits -= modulo
    return decoded.to_bytes(decoded_bits // 8, "big")


def decode_bech32_string(
    bytestring: bytes, constant: int = 1
) -> typing.Tuple[bytes, bytes]:
    hrp, data = parse_bech32(bytestring)
    assert_valid_bech32(hrp, data, constant=constant)
    data = data[:-6]  # discard checksum
    assert data, "empty data"
    payload = bech32_decode(data)
    return hrp, payload


# The following code is found in
# https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#checksum
# but with type hints and docstrings added
#
# Copyright notice per https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#user-content-Copyright
# Copyright (c) 2017 Peter Wiulle / Greg Maxwell
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
# conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
# of conditions and the following disclaimer in the documentation and/or other materials
# provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
# WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


def bech32_polymod(values: typing.List[int]) -> int:
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(s: typing.List[typing.Union[str, bytes]]) -> typing.List[int]:
    return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]


def bech32_verify_checksum(
    hrp: typing.List[typing.Union[str, bytes]],
    data: typing.List[int],
    constant: int = 1,
) -> bool:
    """
    Args:
        data: List[int], data part values including checksum
    """
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == constant


def bech32_create_checksum(
    hrp: typing.List[typing.Union[str, bytes]],
    data: typing.List[int],
    constant: int = 1,
) -> typing.List[int]:
    """
    Args:
        data: List[int], (non-checksum) data part values
    """
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ constant
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
