__version__ = "0.2.2"

import logging
import os
import sys
import typing

from .utils import compact_size_uint
from .utils import is_addr, assert_addr
from .utils import parse_compact_size_uint
from .utils import pubkey
from .utils import pubkey_hash
from .utils import script_hash
from .utils import segwit_addr, decode_segwit_addr, assert_valid_segwit, is_segwit_addr
from .utils import to_bitcoin_address
from .utils import wif_decode
from .utils import wif_encode
from .utils import witness_script_hash

logging.TRACE = logging.DEBUG - 1
logging.addLevelName(logging.TRACE, "TRACE")


class Logger(logging.getLoggerClass()):
    def trace(self, msg, *args, **kwargs):
        if self.isEnabledFor(logging.TRACE):
            self._log(logging.TRACE, msg, args, **kwargs)


logging.setLoggerClass(Logger)


def init_logging(log_level: str):
    """
    Initialize logging with a StreamHandler set to log_level
    Args:
        log_level: str, log level
    """
    log = logging.getLogger(__name__)
    log.setLevel(logging.TRACE)  # set root logger to lowest level
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s] %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    sh.setLevel(getattr(logging, log_level.upper()))
    log.addHandler(sh)
    return log


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
    data: bytes,
    file_: typing.Optional[typing.IO] = None,
    output_format: str = "raw",
):
    """
    Write bytes to file_ or stdout. bin/hex output format will have newline appended
    Args:
        data: bytes, bytes to print
        file_: Optional[IO], file object to write to, if None uses stdout
        output_format: str, 'raw', 'bin', or 'hex'
    """
    if not data:
        return
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
        formatted_data += os.linesep
        if file_ is not None:
            file_.write(formatted_data)
        else:
            sys.stdout.write(formatted_data)
    else:
        raise ValueError(f"unrecognized output format: {output_format}")
