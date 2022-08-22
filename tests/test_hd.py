"""
Test HD wallet code

https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
"""
from hdwallet import HDWallet

from bits.wallet.hd import HD


TEST_MNEMONIC = "pyramid bargain rubber hobby salon thank favorite broccoli stamp scan surround pistol grant reunion hub recipe crystal country exhaust crater scheme brown demise alarm"


def test_root_keys():
    """
    Test master keys from mnemonic match those obtained
    with 3rd party python-hdwallet lib
    https://github.com/meherett/python-hdwallet
    """
    hd_wallet = HDWallet()
    hd_wallet.from_mnemonic(TEST_MNEMONIC)
    hd_wallet_data = hd_wallet.dumps()

    hd = HD.from_mnemonic(TEST_MNEMONIC)
    xprv, xpub = hd.get_root_keys()

    assert hd_wallet_data["root_xprivate_key"] == xprv
    assert hd_wallet_data["root_xpublic_key"] == xpub


def test_paths():
    __paths = [
        "m/0",
        "m/0/0",
        "m/0/0/0",
        "m/44'/0'/0'/0/0",
        "m/44'/0'/0'/0/1",
        "m/44'/0'/0'/0/0",
    ]
    hd_wallet = HDWallet()
    hd_wallet.from_mnemonic(TEST_MNEMONIC)

    hd = HD.from_mnemonic(TEST_MNEMONIC)
    for path in __paths:
        xprv, xpub = hd.get_xkeys_from_path(path)
        hd_wallet.clean_derivation()
        hd_wallet.from_path(path)
        assert xprv == hd_wallet.xprivate_key()
        assert xpub == hd_wallet.xpublic_key()
