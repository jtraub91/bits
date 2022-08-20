import hashlib
import secrets
import unicodedata

from mnemonic import Mnemonic  # TODO: remove this dependency


def generate_mnemonic_phrase(
    strength: int = 256, language: str = "english"
) -> str:
    return Mnemonic(language).to_mnemonic(secrets.token_bytes(strength // 8))


# def get_seed(
#     mnemonic, passphrase: str = "", language: str = "english"
# ) -> bytes:
#     return Mnemonic(language).to_seed(mnemonic, passphrase=passphrase)


# def get_master_key(
#     seed: bytes, language: str = "english", testnet: bool = False
# ) -> bytes:
#     """
#     Arguably defined in BIP32 yet included for master key in python-mnemonic
#     """
#     return Mnemonic(language).to_hd_master_key(seed, testnet=testnet)
# ##
# ###

### From Scratch implementations
##
def to_seed(mnemonic, passphrase: str = "") -> bytes:
    """
    Defined in BIP39
    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
    """
    ITERATIONS = 2048
    return hashlib.pbkdf2_hmac(
        "sha512",
        unicodedata.normalize("NFKD", mnemonic).encode("utf-8"),
        unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8"),
        ITERATIONS,
    )


##
###
