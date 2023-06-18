"""
Parse output descriptors
"""
import logging
import re

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def parse_raw(desc: str) -> bytes:
    """
    Parse HEX from raw script expression
    See https://github.com/bitcoin/bips/blob/master/bip-0385.mediawiki

    Note: Checksum not currently supported
    """
    raw_match = re.search(r"^raw\([0-9a-f]*?\)$", desc)
    raw_w_checksum_match = re.search(r"raw\([0-9a-f]+?\)#.{8}$", desc)
    if raw_w_checksum_match:
        raise ValueError("checksum not supported")
    if not raw_match:
        raise ValueError("raw descriptor match error")
    start, end = raw_match.span()
    hex_expr = desc[start:end].split("raw(")[1].split(")")[0]
    return bytes.fromhex(hex_expr)
