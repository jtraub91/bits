"""
Test expected mempoolaccept response on local bitcoind node via rpc for various transaction types 
"""
import pytest

from bits.script.utils import multisig_script_pubkey
from bits.script.utils import multisig_script_sig
from bits.utils import compute_point
from bits.utils import pubkey

keys = [
    "b45e455f5f4dbd9b1f941a47501fa9ef45c03d2b8ff2b55f8998e9940a5b7dda",
    "38e797abcf8f3505ca9240fdbbecb7c890a70fe6c9366f32ff1b2355c1b5b594",
    "46df122a38bfd63d632c7f7ce2df0d61ccbf0c1352333bc5586c8c7602194f89",
]
pubkeys = [pubkey(compute_point(bytes.fromhex(key)), compressed=True) for key in keys]


@pytest.mark.parametrize(
    "m,pubkeys,keys",
    (
        (1, pubkeys, keys[0:1]),
        (1, pubkeys, keys[1:2]),
        (1, pubkeys, keys[2:]),
        (2, pubkeys, keys[0:2])(2, pubkeys, keys[1:]),
        (2, pubkeys, [keys[0], keys[2]])(3, pubkeys, keys),
    ),
)
def test_mempoolaccept_multisig(m, pubkeys, keys):
    multisig_scriptpubkey = multisig_script_pubkey(m, pubkeys)


def test_mempoolaccept_error_multisig(m, pubkeys, keys):
    return
