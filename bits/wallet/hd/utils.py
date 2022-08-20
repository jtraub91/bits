import json
import hashlib
from typing import Union

from base58 import b58decode

from bits.utils import pub_point, pubkey_hash, base58check
from bits.wallet.hd.bip32 import CKDpriv, CKDpub

import bits.wallet.hd.bip43 as bip43
from bits.wallet.hd.bip32 import to_master_key, CKDpriv, CKDpub, ser_p
from bits.wallet.hd.bip39 import generate_mnemonic_phrase, to_seed


HARDENED_OFFSET = 0x80000000


def derive_from_path(
    path: str,
    master_extended_key: Union[
        tuple[int, bytes], tuple[tuple[int, int], bytes]
    ],
) -> Union[str, bytes]:
    """
    Derive extended keys
    from path and master extended key
    """
    # path validation
    if path.startswith("m/"):
        function = CKDpriv
    elif path.startswith("M/"):
        function = CKDpub
    else:
        raise ValueError("path must start with m/ or M/")
    tree_ = path.split("/")[1:]
    try:
        for t in tree_:
            if t.endswith("'"):
                val = t
                int(val[:-1])
            else:
                val = t
                int(val)
    except ValueError:
        raise ValueError(f"check path value: {val}")

    # parse tree values in integer form
    tree = [
        int(t) if not t.endswith("'") else int(t[:-1]) + HARDENED_OFFSET
        for t in tree_
    ]

    i = tree[0]
    result = function(master_extended_key[0], master_extended_key[1], i)
    for i in tree[1:]:
        result = function(result[0], result[1], i)
    return result


def p2pkh(xpub):
    """
    Return p2pkh bitcoin address from xpub
    """
    decoded_xpub_bytes = b58decode(xpub)
    checksum = decoded_xpub_bytes[-4:]
    checksum_check = hashlib.sha256(
        hashlib.sha256(decoded_xpub_bytes[:-4]).digest()
    ).digest()
    assert checksum == checksum_check[:4]
    payload = decoded_xpub_bytes[4:-4]  # remove 4 byte version and checksum

    pubkey_ = payload[-33:]  # last 33 bytes is pubkey in SEC1 compressed form

    version = b"\x00"
    pkh = pubkey_hash(pubkey_)
    return base58check(version, pkh).decode("ascii")


class HD:
    """
    BIP44, BIP43, BIP39, BIP32 compatible wallet
    """

    mnemonic: str = ""

    def __init__(
        self,
        passphrase: str = "",
        strength: int = 256,
        language: str = "english",
    ):
        if not self.mnemonic:
            self.mnemonic = generate_mnemonic_phrase(
                strength=strength, language=language
            )
        self.seed = to_seed(self.mnemonic, passphrase=passphrase)
        self.extended_master_key = to_master_key(self.seed)

    @classmethod
    def from_mnemonic(cls, mnemonic, passphrase: str = ""):
        cls.mnemonic = mnemonic
        return cls(passphrase=passphrase)

    def get_root_keys(self) -> tuple[str]:
        """
        Return tuple of serialized master (root) keys (xpub/xprv)
        base58(check) encoding
        Args:
            public: bool, True for xpub else xprv
        """
        xprv = bip43.root_serialized_extended_key(
            self.extended_master_key[0],
            self.extended_master_key[1],
        ).decode("ascii")
        xpub = bip43.root_serialized_extended_key(
            pub_point(self.extended_master_key[0]),
            self.extended_master_key[1],
            public=True,
        ).decode("ascii")
        return xprv, xpub

    def get_xkeys_from_path(self, path: str):
        """
        Derives xkeys from path and class master extended private key
        Args:
            path: str, path to extended key, e.g. m/44'/0'/0'/0/0
        Returns:
            xprv, xpub
        """
        xprv = derive_from_path(path, self.extended_master_key)
        xpub = derive_from_path(
            path,
            (
                pub_point(self.extended_master_key[0]),
                self.extended_master_key[1],
            ),
        )
        return xprv, xpub

    def get_address_from_path(self, path, type="p2pkh"):
        return

    def scan_for_utxo(self):
        """
        Scan blockchain for utxo owned by this wallet
        https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#address-gap-limit
        """
        return


if __name__ == "__main__":
    hd = HD()
    print(hd.get_root_keys())
