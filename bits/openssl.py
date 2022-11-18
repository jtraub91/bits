"""
Collection of subprocess calls to openssl for convenience
"""
import os
import platform
from subprocess import PIPE
from subprocess import Popen

SYSTEM = platform.system()
if SYSTEM == "Linux":
    OPENSSL_ = "openssl"
elif SYSTEM == "Windows":
    OPENSSL_ = "C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe"

with Popen([OPENSSL_, "help"], stdout=PIPE, stderr=PIPE) as proc:
    proc.communicate()

if proc.returncode:
    raise OSError(f"openssl dependency seems to be missing or broken")


def genkey(save_as: str = "", curve: str = "secp256k1"):
    cmd = f"{OPENSSL_} ecparam -name {curve} -genkey -noout "
    if save_as:
        cmd += f"-out {save_as}"
    with Popen(cmd.split(), stdout=PIPE) as proc:
        stdout, _ = proc.communicate()
    return stdout


def public_pem_from_secret_pem(from_pem: str, save_as="", compressed: bool = True):
    cmd = f"{OPENSSL_} ec -in {from_pem} -pubout "
    if save_as:
        cmd += f"-out {save_as} "
    if compressed:
        cmd += "-conv_form compressed "
    with Popen(cmd.split(), stdout=PIPE, stderr=PIPE) as proc:
        stdout, _ = proc.communicate()
    return stdout


def public_key_hex_from_public_pem(from_pem: str):
    if SYSTEM == "Windows":
        cwd = "C:\\Users\\Jason\\WebProjects\\bits"
        abspath = os.path.join(cwd, from_pem)
        cmd = f'"{OPENSSL_}" ec -in {abspath} -pubin -text '
    elif SYSTEM == "Linux":
        cmd = f"{OPENSSL_} ec -in {from_pem} -pubin -text | grep -E \"[a-f0-9][a-f0-9]:\" | tr -d ' ' | tr -d ':' | tr -d '\\n'"
    print(cmd)

    with Popen(
        cmd.split(),
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
    ) as proc:
        stdout, stderr = proc.communicate()

    # if SYSTEM == "Windows":
    #     return

    return stdout, stderr
