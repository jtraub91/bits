import os

import pytest

from bits.config import Config
from bits.integrations import generate_funded_keys


config_dir = os.environ.get(
    "BITS_DATADIR", os.path.join(os.path.expanduser("~"), ".bits")
)
config = Config()
config.load_config(config_dir=config_dir)


@pytest.fixture(scope="module")
def funded_keys_101():
    return generate_funded_keys(
        101,
        network="regtest",
        rpc_url=config.rpc_url,
        rpc_datadir=config.rpc_datadir,
        rpc_user=config.rpc_user,
        rpc_password=config.rpc_password,
    )
