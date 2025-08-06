"""
PEM / DER / ASN.1
"""
import base64
import math
import os
import re
import typing

import bits.ecmath

# monkeypatch base64 global variables for proper PEM encoding
# via base64.encodebytes
base64.MAXLINESIZE = 64
base64.MAXBINSIZE = (base64.MAXLINESIZE // 4) * 3


def decode_base64_pem(pem: bytes) -> bytes:
    """
    Decode pem base64 data
    inspiration from ssl.PEM_cert_to_DER_cert
    but more general
    """
    pem_ = pem.strip()
    header_re = b"-----BEGIN .+-----"
    footer_re = b"-----END .+-----"
    header_search = re.search(header_re, pem_)
    if not header_search or header_search.start() != 0:
        raise ValueError("encoding error; must start with pem header")
    footer_search = re.search(footer_re, pem_)
    if not footer_search or footer_search.end() != len(pem_):
        raise ValueError("encoding error; must end with pem footer")
    d = pem_[header_search.end() : footer_search.start()].strip()
    return base64.decodebytes(d)


def decode_pem(pem_: bytes):
    """
    Decode pem and parse ASN.1
    """
    der = decode_base64_pem(pem_)
    return der


def encode_pem(
    der_: bytes,
    header: bytes = b"-----BEGIN CERTIFICATE-----",
    footer: bytes = b"-----END CERTIFICATE-----",
) -> bytes:
    return (
        header
        + os.linesep.encode("utf8")
        + base64.encodebytes(der_)
        + footer
        + os.linesep.encode("utf8")
    )


# https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#tag
TAG_MAP: typing.Dict[int, str] = {
    0x02: "INTEGER",
    0x03: "BIT STRING",
    0x04: "OCTET STRING",
    0x05: "NULL",
    0x06: "OBJECT IDENTIFIER",
    0x0C: "UTF8String",
    0x10: "SEQUENCE (OF)",
    0x11: "SET (OF)",
}
MAP_TAG: typing.Dict[str, int] = {value: key for key, value in TAG_MAP.items()}
# tag classes
#   bit 6: 1=constructed 0=primitive
#   | class            | bit 8 | bit 7 |
#    ------------------ ------- -------
#   | universal        |   0   |   0   |
#   | application      |   0   |   1   |
#   | context-specific |   1   |   0   |
#   | private          |   1   |   1   |
# https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#tag-classes
TAG_CLASS_MAP = {
    0b00: "Universal",
    0b01: "Application",
    0b10: "Context-specific",
    0b11: "Private",
}
MAP_CLASS_TAG = {value: key for key, value in TAG_CLASS_MAP.items()}


def encode_parsed_asn1_val(tag: int, parsed_val: typing.Union[list, bytes]) -> bytes:
    encoded = b""
    if tag & 0x1F in [MAP_TAG["SEQUENCE (OF)"], 0x00, 0x01]:
        for val in parsed_val:
            encoded += encode_parsed_asn1(val)
    elif tag & 0x1F in [
        MAP_TAG["INTEGER"],
        MAP_TAG["OCTET STRING"],
        MAP_TAG["BIT STRING"],
    ]:
        encoded += parsed_val
    elif tag & 0x1F == MAP_TAG["OBJECT IDENTIFIER"]:
        if parsed_val == "id-ecPublicKey":
            oid = "1.2.840.10045.2.1"
        elif parsed_val == "id-ansip256k1":
            oid = "1.3.132.0.10"
        else:
            oid = parsed_val
        encoded += encode_oid(oid)
    return encoded


def encode_parsed_asn1(parsed_data: list) -> bytes:
    """
    Inverse of parse_asn1
    >>> sig = bytes.fromhex("3046022100807ebfaf104a08061044a11109873af5c16cfb2e4e4ec69b47bd4dfcf3b630d4022100bbc3387cc3c5fd83d672eee20c40161099f8df44e135ca96a9b8650dbcbfe1bc")
    >>> parsed = parse_asn1(sig)
    >>> encoded = encode_parsed_asn1(parsed[0])
    >>> assert sig == encoded
    """
    encoded = b""
    tag_tuple, length, parsed_data = parsed_data[0], parsed_data[1], parsed_data[2]
    tag, tag_constructed, tag_class = tag_tuple
    tag_int = MAP_TAG[tag] if type(tag) is str else tag
    if tag_constructed == "Constructed":
        tag_int |= 0b00100000
    tag_int |= MAP_CLASS_TAG[tag_class] << 6
    encoded += tag_int.to_bytes(1, "big") + length.to_bytes(1, "big")
    encoded += encode_parsed_asn1_val(tag_int, parsed_data)
    return encoded


# https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
def parse_asn1(data: bytes):
    """
    Parse ASN.1 data
    Recursive for SEQUENCE (OF) tag
    """
    parsed = []
    while data:
        tag = data[0]
        length = data[1]
        value = data[2 : 2 + length]
        parsed.append(
            [
                [
                    TAG_MAP.get(tag & 0b00011111, tag & 0b00011111),
                    "Constructed" if tag & 0b00100000 else "Primitive",
                    TAG_CLASS_MAP[tag >> 6],
                ],
                length,
                parse_asn1_value(tag, value),
            ]
        )
        data = data[2 + length :]
    return parsed


def parse_asn1_value(tag: int, value: bytes):
    """
    Parse ASN.1 tag's value
    """
    tag_constructed = tag & 0b00100000
    tag_class = tag >> 6
    tag = tag & 0b00011111
    if tag == MAP_TAG["SEQUENCE (OF)"]:
        return parse_asn1(value)
    elif tag == MAP_TAG["OBJECT IDENTIFIER"]:
        oid = parse_oid(value)
        # https://oidref.com/
        if oid == "1.2.840.10045.2.1":
            oid = "id-ecPublicKey"
        elif oid == "1.3.132.0.10":
            oid = "id-ansip256k1"
        return oid
    elif tag_constructed:
        return parse_asn1(value)
    else:
        return value


def encode_oid(oid: str) -> bytes:
    """
    https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
    >>> encode_oid("1.2.840.10045.2.1").hex()
    '2a8648ce3d0201'
    >>> encode_oid("1.3.6.1.4.1.311.21.20").hex()
    '2b0601040182371514'
    >>> encode_oid("1.3.132.0.10").hex()
    '2b8104000a'
    """
    encoded = b""
    nodes = oid.split(".")
    first_byte = (int(nodes[0]) * 40 + int(nodes[1])).to_bytes(1, "big")
    encoded += first_byte
    for node in nodes[2:]:
        if int(node) < 128:
            # encode node as single byte
            encoded += int(node).to_bytes(1, "big")
        else:
            # encode node as multiple bytes
            number_of_bytes = (int(node).bit_length() + 8) // 8
            vlq_bits = format(int(node), f"0{7 * number_of_bytes}b")
            vlq_bytes_bits = [
                vlq_bits[7 * i : 7 * i + 7] for i in range(number_of_bytes)
            ]
            # prepend '1' to all bytes except last
            encoded_bytes_bits = ["1" + byte_bits for byte_bits in vlq_bytes_bits[:-1]]
            # prepend '0' to last byte
            encoded_bytes_bits += ["0" + vlq_bytes_bits[-1]]
            for encoded_byte_bits in encoded_bytes_bits:
                encoded += int(encoded_byte_bits, 2).to_bytes(1, "big")
    return encoded


def parse_oid(data: bytes) -> str:
    """
    >>> parse_oid(bytes.fromhex("2a8648ce3d0201"))
    '1.2.840.10045.2.1'
    >>> parse_oid(bytes.fromhex("2b8104000a"))
    '1.3.132.0.10'
    """
    # https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
    # relevant OIDS:
    #   id-ecPublicKey: 1.2.840.10045.2.1
    nodes = []
    # 1st byte = node1 * 40 + node2
    first_byte = data[0]
    first_node = first_byte // 40
    second_node = first_byte % 40
    nodes.append(first_node)
    nodes.append(second_node)
    data = data[1:]
    while data:
        i = 0
        first_byte = data[i]
        leftmost_bit = first_byte & 0b10000000
        if leftmost_bit:
            # https://stackoverflow.com/a/24720842
            vlq_bytes = [first_byte]
            while leftmost_bit:
                i += 1
                next_byte = data[i]
                vlq_bytes.append(next_byte)
                leftmost_bit = next_byte & 0b10000000
            data = data[i + 1 :]
            # concatenate lower 7 bits of each vlq_byte, read as int
            # vlq_bytes = [vlq_byte & 0x7F for vlq_byte in vlq_bytes]
            vlq_bytes_bits = [
                (
                    vlq_byte & 0x40,
                    vlq_byte & 0x20,
                    vlq_byte & 0x10,
                    vlq_byte & 0x8,
                    vlq_byte & 0x4,
                    vlq_byte & 0x2,
                    vlq_byte & 0x1,
                )
                for vlq_byte in vlq_bytes
            ]
            no_bits = len(vlq_bytes_bits) * 7
            no_bytes = 8 * math.ceil(no_bits / 8)
            node_value = 0
            for byte_idx, vlq_byte_bits in enumerate(
                reversed(vlq_bytes_bits)
            ):  # reversed i.e. bytes lsb first
                for bit_idx, vlq_byte_bit in enumerate(
                    reversed(vlq_byte_bits)
                ):  # reversed i.e. bits lsb first
                    node_value = (
                        node_value | (0x1 << (bit_idx + (byte_idx * 7)))
                        if vlq_byte_bit
                        else node_value
                    )
            nodes.append(node_value)
        else:
            nodes.append(first_byte)
            data = data[i + 1 :]
    return ".".join([str(node) for node in nodes])


def der_encode_sig(r: int, s: int) -> bytes:
    # https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#der-encoding
    r_number_of_bytes = (r.bit_length() + 7) // 8
    r_bytes = r.to_bytes(r_number_of_bytes, "big")
    if r_bytes[0] >= 0x80:
        r_bytes = b"\x00" + r_bytes

    s_number_of_bytes = (s.bit_length() + 7) // 8
    s_bytes = s.to_bytes(s_number_of_bytes, "big")
    if s_bytes[0] >= 0x80:
        s_bytes += b"\x00" + s_bytes

    signature_asn1_data_struct = [
        [
            ["SEQUENCE (OF)", "Constructed", "Universal"],
            len(r_bytes) + len(s_bytes) + 4,
            [
                [
                    ["INTEGER", "Primitive", "Universal"],
                    len(r_bytes),
                    r_bytes,
                ],
                [
                    ["INTEGER", "Primitive", "Universal"],
                    len(s_bytes),
                    s_bytes,
                ],
            ],
        ]
    ]
    return encode_parsed_asn1(signature_asn1_data_struct[0])


def der_decode_sig(der: bytes) -> typing.Tuple[int, int]:
    parsed = parse_asn1(der)
    r = int.from_bytes(parsed[0][2][0][2], "big")
    s = int.from_bytes(parsed[0][2][1][2], "big")
    return r, s


def pem_decode_key(
    pem_: bytes,
) -> typing.Union[typing.Tuple[bytes, bytes], typing.Tuple[bytes]]:
    """
    Decode from pem / der encoded EC private / public key
    Returns:
        (privkey, pubkey) or pubkey, respectively
    """
    decoded = decode_pem(pem_)
    parsed = parse_asn1(decoded)
    if parsed[0][2][0][2] == b"\x01":
        return parsed[0][2][1][2], parsed[0][2][3][2][0][2][1:]
    elif parsed[0][2][0][2][0][2] == "id-ecPublicKey":
        return (parsed[0][2][1][2][1:],)
    else:
        raise ValueError("could not identify data as private nor public key")


def pem_encode_key(key_: bytes) -> bytes:
    """
    Encode (pub)key as pem
    """
    if len(key_) == 32:
        # private secp256k1 key
        parsed_data_struct = [
            [
                ["SEQUENCE (OF)", "Constructed", "Universal"],
                116,
                [
                    [["INTEGER", "Primitive", "Universal"], 1, b"\x01"],
                    [
                        ["OCTET STRING", "Primitive", "Universal"],
                        32,
                        key_,
                    ],
                    [
                        [0, "Constructed", "Context-specific"],
                        7,
                        [
                            [
                                ["OBJECT IDENTIFIER", "Primitive", "Universal"],
                                5,
                                "id-ansip256k1",
                            ]
                        ],
                    ],
                    [
                        [1, "Constructed", "Context-specific"],
                        68,
                        [
                            [
                                ["BIT STRING", "Primitive", "Universal"],
                                66,
                                b"\x00" + bits.pubkey(*bits.ecmath.compute_point(key_)),
                            ]
                        ],
                    ],
                ],
            ]
        ]
        return encode_pem(
            encode_parsed_asn1(parsed_data_struct[0]),
            header=b"-----BEGIN EC PRIVATE KEY-----",
            footer=b"-----END EC PRIVATE KEY-----",
        )
    elif len(key_) == 33 or len(key_) == 65:
        parsed_data_struct = [
            [
                ["SEQUENCE (OF)", "Constructed", "Universal"],
                86 if len(key_) == 65 else 54,
                [
                    [
                        ["SEQUENCE (OF)", "Constructed", "Universal"],
                        16,
                        [
                            [
                                ["OBJECT IDENTIFIER", "Primitive", "Universal"],
                                7,
                                "id-ecPublicKey",
                            ],
                            [
                                ["OBJECT IDENTIFIER", "Primitive", "Universal"],
                                5,
                                "id-ansip256k1",
                            ],
                        ],
                    ],
                    [
                        ["BIT STRING", "Primitive", "Universal"],
                        66 if len(key_) == 65 else 34,
                        b"\x00" + key_,
                    ],
                ],
            ]
        ]
        return encode_pem(
            encode_parsed_asn1(parsed_data_struct[0]),
            header=b"-----BEGIN PUBLIC KEY-----",
            footer=b"-----END PUBLIC KEY-----",
        )
    else:
        raise ValueError(
            "key (based on len) not recognized as public nor private key data"
        )


def ensure_sig_low_s(sig_: bytes) -> bytes:
    """
    Ensure DER encoded signature has low enough s value
    https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures

    OpenSSL does not ensure this by default
    https://bitcoin.stackexchange.com/a/59826/135678
    Apparently, Bitcoin Core used to do this to get around it
    https://github.com/bitcoin/bitcoin/blob/v0.9.0/src/key.cpp#L204L224

    Essentially just use s = N - s if s > N / 2
    """
    parsed = parse_asn1(sig_)
    # r_val = int.from_bytes(parsed[0][2][0][2], "big")
    r_len = parsed[0][2][0][1]
    s_val = int.from_bytes(parsed[0][2][1][2], "big")
    s_len = parsed[0][2][1][1]
    if s_val > bits.ecmath.SECP256K1_N // 2 or s_val < 1:
        # s_val = SECP256K1_N - s_val
        s_val = bits.ecmath.sub_mod_p(0, s_val, p=bits.ecmath.SECP256K1_N)
        parsed[0][2][1][2] = s_val.to_bytes(32, "big")
        parsed[0][2][1][1] = 32
        parsed[0][1] = 32 + r_len + 4
        encoded = encode_parsed_asn1(parsed[0])
        return encoded
    return sig_


def pubkey_from_pem(pem_: bytes):
    decoded_key = pem_decode_key(pem_)
    if len(decoded_key) == 2:
        return decoded_key[1]
    return decoded_key
