from subprocess import PIPE
from subprocess import Popen

import ecdsa


def generate_keypair(save_as=""):
    """
    UNSAFE ¯\_(ツ)_/¯
    Return new privkey, (pubkey_x, pubkey_y)
    Optionally, save as pem file
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if save_as:
        with open(save_as, "wb") as pem_file:
            pem = sk.to_pem()
            pem_file.write(pem)
    return sk.privkey.secret_multiplier, (
        vk.pubkey.point.x(),
        vk.pubkey.point.y(),
    )


def load_pubkey(filename: str, format: str = "pem") -> bytes:
    raise NotImplementedError
