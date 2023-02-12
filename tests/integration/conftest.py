import pytest

from bits.integrations import generate_funded_keys


@pytest.fixture(scope="module")
def funded_keys_101():
    return generate_funded_keys(101, network="regtest")
