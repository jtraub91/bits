import json
import logging
import os
import sys
from typing import IO
from typing import Optional
from typing import Union

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
sh.setLevel(logging.ERROR)
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


def print_bytes(data: bytes, output_format: str = "raw"):
    """
    Print bytes to console
    Args:
        data: bytes, bytes to print
    """
    if output_format == "raw":
        sys.stdout.buffer.write(data)
    elif output_format == "bin" or output_format == "hex":
        format_spec = (
            f"0{len(data) * 2}x" if output_format == "hex" else f"0{len(data) * 8}b"
        )
        print(format(int.from_bytes(data, "big"), format_spec))
    else:
        raise ValueError(f"unrecognized output format: {output_format}")


bitsconfig = {}
load_config()
