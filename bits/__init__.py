import json
import logging
import os
import sys
from typing import IO
from typing import Optional
from typing import Union

from .utils import compact_size_uint
from .utils import compute_point
from .utils import d_hash
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

try:
    import tomllib

    HAS_TOMLLIB = True
except ImportError:
    HAS_TOMLLIB = False


log = logging.getLogger(__name__)
formatter = logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s] %(message)s")
if not os.path.exists(".bits/logs"):
    os.makedirs(".bits/logs")
fh = logging.FileHandler(".bits/logs/bits.log")
fh.setFormatter(formatter)
log.addHandler(fh)
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
sh.setFormatter(formatter)
log.addHandler(sh)


def set_log_level(level: str):
    if level.lower() not in ["info", "debug", "warning", "critical", "error"]:
        raise ValueError(f"log level not supported: {level}")
    log.setLevel(getattr(logging, level.upper()))
    return True


def default_config():
    return {
        "network": "mainnet",
        "logfile": ".bits/logs/bits.log",
        "loglevel": "info",
        "rpcurl": "",
        "rpcuser": "",
        "rpcpassword": "",
        "input_format": "bin",
        "output_format": "bin",
    }


def load_config():
    global bitsconfig
    bitsconfig = default_config()
    bitsconfig_file = (
        open(".bitsconfig.toml", "rb") if HAS_TOMLLIB else open(".bitsconfig.json")
    )
    bitsconfig_file_dict = (
        tomllib.load(bitsconfig_file) if HAS_TOMLLIB else json.load(bitsconfig_file)
    )
    bitsconfig.update(bitsconfig_file_dict)
    bitsconfig_file.close()


def read_bytes(file_: Optional[IO] = None, input_format: str = "raw") -> bytes:
    """
    Read from optional file or stdin and convert to bytes
    Args:
        input_format: str, "raw", "hex", or "bin"
    """
    if input_format == "raw":
        data = file_.buffer.read().strip() if file_ else sys.stdin.buffer.read().strip()
    elif input_format == "hex":
        data = file_.read().strip() if file_ else sys.stdin.read().strip()
        data = bytes.fromhex(data)
    elif input_format == "bin":
        data = file_.read().strip() if file_ else sys.stdin.read().strip()
        data = int(data, 2).to_bytes(len(data) // 8, "big")
    else:
        raise ValueError(f"unrecognized input format: {input_format}")
    return data


def write_bytes(data: bytes, file_: Optional[IO] = None, output_format: str = "raw"):
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


bitsconfig = {}
load_config()
