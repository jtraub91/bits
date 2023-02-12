"""
Collection of subprocess calls to openssl for convenience
"""
import logging
import os
import platform
import sys
from subprocess import PIPE
from subprocess import Popen
from typing import List

log = logging.getLogger(__name__)

SYSTEM = platform.system()
if SYSTEM == "Linux" or SYSTEM == "Darwin":
    OPENSSL_ = "openssl"
elif SYSTEM == "Windows":
    OPENSSL_ = "C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe"

with Popen([OPENSSL_, "help"], stdout=PIPE, stderr=PIPE) as proc:
    proc.communicate()

if proc.returncode:
    raise OSError(f"openssl dependency seems to be missing or broken")


def genkey(out: str = "", curve: str = "secp256k1"):
    cmd = f"{OPENSSL_} ecparam -name {curve} -genkey -noout "
    if out:
        cmd += f"-out {out}"
    with Popen(cmd.split(), stdout=PIPE) as proc:
        stdout, _ = proc.communicate()
    return stdout


def pubkey_pem(in_: str = "", out: str = "", compressed: bool = True):
    """
    Return public key from secret key
    Args:
        in_: str, reads from sys.stdin if not specified else secret key input filename
        out: str, output filename
        compressed: bool, True to output compressed pubkey
    """
    cmd = f"{OPENSSL_} ec -pubout "
    stdin = b""
    if in_:
        cmd += f"-in {in_} "
    else:
        stdin = "".join([line for line in sys.stdin]).encode("utf8")
    if out:
        cmd += f"-out {out} "
    if compressed:
        cmd += "-conv_form compressed "
    with Popen(cmd.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE) as proc:
        stdout, _ = proc.communicate(input=stdin)
    return stdout


def sign(privkey_file: str, files: List[str] = [], stdin: bytes = None):
    """
    Sign file(s) with private key file. If no file(s) specified, stdin is used.
    Args:
        privkey_file: str, filename of private key
        files: List[str], list of filenames to be signed
    """
    cmd = f"openssl dgst -sha256 -sign {privkey_file} "
    if files:
        cmd += " ".join(files)
    with Popen(cmd.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE) as proc:
        stdout, stderr = proc.communicate(stdin)
        if stderr:
            log.error(stderr)
    return stdout


def verify(pubkey_file, signature_file, files: List[str] = []):
    """
    Verify signature and file(s) with public key file. If no file(s) specified, stdin is used.
    """
    cmd = f"openssl dgst -sha256 -verify {pubkey_file} -signature {signature_file} "
    if files:
        cmd += " ".join(files)
    with Popen(cmd.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE) as proc:
        stdout, stderr = proc.communicate()
    return stdout
