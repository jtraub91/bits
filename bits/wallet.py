"""
Wallet utils
"""
import secrets

from mnemonic import Mnemonic  # BIP39 ref impl


class HD:
    """
    BIP32, BIP39, BIP43, BIP44
    """

    def __init__(self, language: str = "english", strength: int = 256):
        self.mnemonic = None
        self.strength = None
        self.__generate(language=language, strength=strength)

    def __generate(self, language: str = "english", strength: int = 256):
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError(f"Not valid strength (entropy): {strength}")

        if self.mnemonic is None:
            mnemo = Mnemonic(language)
            self.mnemonic = mnemo.to_mnemonic(secrets.token_bytes(strength // 8))
            self.strength = strength
            self.language = language
            assert mnemo.check(self.mnemonic)
        else:
            raise ValueError("Mnemonic seed already generated")

    def get_seed(self, passphrase: str = "") -> bytes:
        return Mnemonic(self.language).to_seed(self.mnemonic, passphrase=passphrase)

    def get_master_key(self, passphrase: str = "") -> bytes:
        return Mnemonic(self.language).to_hd_master_key(self.get_seed(passphrase))
