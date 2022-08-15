"""
Test bip32.py

Test vectors in BIP 32
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
"""

from bits.btypes import bitcoin_address
from bits.wallet.hd.bip32 import to_master_key, serialize
from bits.wallet.hd.bip39 import (
    to_seed,
    generate_mnemonic_phrase,
    get_seed,
    get_master_key,
)


def test_master_key_generated_from_scratch_matches_master_key_generated_with_python_mnemonic():
    phrase = generate_mnemonic_phrase()
    mk_1 = get_master_key(get_seed(phrase))

    seed = to_seed(phrase)
    master_key, master_chain_code = to_master_key(seed)

    mk_2 = bitcoin_address(
        serialize(b"\x00" + master_key, master_chain_code, master=True), version=b""
    ).decode("ascii")
    assert mk_1 == mk_2
