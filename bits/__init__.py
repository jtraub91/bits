__version__ = "0.1.0"

import json
import logging
import os
import sys
import typing

try:
    import tomllib

    HAS_TOMLLIB = True
except ImportError:
    HAS_TOMLLIB = False

from .utils import compact_size_uint
from .utils import compute_point
from .utils import hash160
from .utils import hash256
from .utils import is_point
from .utils import parse_compact_size_uint
from .utils import pem_encode_key
from .utils import point
from .utils import pubkey
from .utils import pubkey_hash
from .utils import ripemd160
from .utils import script_hash
from .utils import sha256
from .utils import sig
from .utils import sig_verify
from .utils import to_bitcoin_address
from .utils import wif_decode
from .utils import wif_encode
from .utils import witness_script_hash


def setup_logging(bitsconfig: dict):
    log = logging.getLogger(__name__)
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s] %(message)s")
    if not os.path.exists(bitsconfig["logfile"].split()[0]):
        os.makedirs(bitsconfig["logfile"].split()[0])
    fh = logging.FileHandler(bitsconfig["logfile"])
    fh.setFormatter(formatter)
    fh.setLevel(bitsconfig.get("logfile_loglevel", "info"))
    log.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    sh.setLevel(bitsconfig.get("loglevel", "error"))
    log.addHandler(sh)
    return log


def default_config():
    return {
        "network": "mainnet",
        "logfile": os.path.join(os.path.expanduser("~"), ".bits/logs/bits.log"),
        "loglevel": "info",
        "input_format": "hex",
        "output_format": "hex",
    }


def load_config():
    bitsconfig = default_config()
    bitsconfig_file_dict = {}
    if HAS_TOMLLIB and os.path.exists(".bitsconfig.toml"):
        with open(".bitsconfig.toml", "rb") as bitsconfig_file:
            bitsconfig_file_dict = tomllib.load(bitsconfig_file)
    elif os.path.exists(".bitsconfig.json"):
        with open(".bitsconfig.json") as bitsconfig_file:
            bitsconfig_file_dict = json.load(bitsconfig_file)
    bitsconfig.update(bitsconfig_file_dict)
    return bitsconfig


def read_bytes(
    file_: typing.Optional[typing.IO] = None, input_format: str = "raw"
) -> bytes:
    """
    Read from optional file or stdin and convert to bytes

    Any newlines will be stripped from beginning / end for hex and bin, only.
    Raw is read without any additional processing.

    Furthermore, hex and bin will be left-zero-padded to the nearest byte, if they are
    not provided in 8-bit multiples.

    Args:
        file_: Optional[IO], optional file object - otherwise stdin is used
        input_format: str, "raw", "hex", or "bin"
    Returns:
        data as bytes
    """
    if input_format == "raw":
        data = file_.buffer.read() if file_ else sys.stdin.buffer.read()
    elif input_format == "hex":
        data = file_.read().strip() if file_ else sys.stdin.read().strip()
        if len(data) % 2:
            data = "0" + data
        data = bytes.fromhex(data)
    elif input_format == "bin":
        data = file_.read().strip() if file_ else sys.stdin.read().strip()
        if len(data) % 8:
            data = "0" * (8 - len(data) % 8) + data
        data = int(data, 2).to_bytes(len(data) // 8, "big")
    else:
        raise ValueError(f"unrecognized input format: {input_format}")
    return data


def write_bytes(
    data: bytes, file_: typing.Optional[typing.IO] = None, output_format: str = "raw"
):
    """
    Write bytes to outfile or stdout
    Args:
        data: bytes, bytes to print
    """
    if output_format == "raw":
        if file_ is not None:
            file_.buffer.write(data)
        else:
            sys.stdout.buffer.write(data)
    elif output_format == "bin" or output_format == "hex":
        format_spec = (
            f"0{len(data) * 2}x" if output_format == "hex" else f"0{len(data) * 8}b"
        )
        formatted_data = format(int.from_bytes(data, "big"), format_spec)
        if file_ is not None:
            file_.write(formatted_data)
        else:
            print(formatted_data)
    else:
        raise ValueError(f"unrecognized output format: {output_format}")


bitsconfig = load_config()
