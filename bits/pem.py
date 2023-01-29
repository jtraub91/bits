"""
PEM / DER / ASN.1
"""
import base64
import math
import re
import typing


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
    return header + b"\n" + base64.encodebytes(der_) + b"\n" + footer


def decode_key(pem_: bytes) -> typing.Union[tuple[bytes, bytes], bytes]:
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
        return parsed[0][2][1][2][1:]
    else:
        raise ValueError("could not identify data as private nor public key")


# https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#tag
TAG_MAP = {
    0x02: "INTEGER",
    0x03: "BIT STRING",
    0x04: "OCTET STRING",
    0x05: "NULL",
    0x06: "OBJECT IDENTIFIER",
    0x0C: "UTF8String",
    0x10: "SEQUENCE (OF)",
    0x11: "SET (OF)",
}
MAP_TAG = {value: key for key, value in TAG_MAP.items()}
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
    if tag & 0x1F == MAP_TAG["SEQUENCE (OF)"]:
        for val in parsed_val:
            encoded += encode_parsed_asn1(val)
    elif tag & 0x1F == MAP_TAG["INTEGER"]:
        encoded += parsed_val
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
    tag_int = MAP_TAG[tag]
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
        if oid == "1.2.840.10045.2.1":
            oid = "id-ecPublicKey"
        return oid
    elif tag_constructed:
        return parse_asn1(value)
    else:
        return value


def parse_oid(data: bytes) -> str:
    """
    >>> parse_oid(bytes.fromhex("2a8648ce3d0201"))
    '1.2.840.10045.2.1'
    """
    # https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
    # relevant OIDS:
    #   id-ecPublicKey: 1.2.840.10045.2.1
    nodes = []
    # 1st byte = node1 * 40 + node2
    first_byte = data[0]
    first_node = int(first_byte / 40)
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
