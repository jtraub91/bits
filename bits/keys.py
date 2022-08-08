from subprocess import Popen, PIPE

import ecdsa


def generate_keypair(save_as=""):
    """
    Return new privkey, (pubkey_x, pubkey_y)
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if save_as:
        with open(save_as, "wb") as pem_file:
            pem = sk.to_pem()
            pem_file.write(pem)
    return sk.privkey.secret_multiplier, (vk.pubkey.point.x(), vk.pubkey.point.y())

def genkey_openssl(filename):
    with Popen(f"openssl ecparam -name secp256k1 -genkey -noout -out {filename}".split()) as proc:
        ret = proc.communicate()
