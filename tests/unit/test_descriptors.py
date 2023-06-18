import pytest

from bits.descriptors import parse_raw


@pytest.mark.parametrize(
    "descriptor",
    (
        # "pk(0409877767e14ced28c647a9c0121b1e5761c788d3c08c8302d874ff610f7055e8baf3595511297608b25f2d698e4f4edff8e71884e56ea03a159602762e0512e2)",
        # "pk(0332647ac7f24148b610ed9643abfec2e72f684cbab27c71b6b044ea45f450d6c3)",
        # "addr(moUS3P3bFiauE3ettzvsU7djgUEFfZ1f2r)",
        # "addr(1HtwbNKMjCET6ESnUFKJFgaUbMCXpLBdJE)",
        "raw(0332647ac7f24148b610ed9643abfec2e72f684cbab27c71b6b044ea45f450d6c3)",
        "raw(6a0b68656c6c6f20776f726c64)",
    ),
)
def test_valid_descriptors(descriptor):
    parsed = parse_raw(descriptor)


@pytest.mark.parametrize(
    "descriptor",
    (
        # "pk(0109877767e14ced28c647a9c0121b1e5761c788d3c08c8302d874ff610f7055e8baf3595511297608b25f2d698e4f4edff8e71884e56ea03a159602762e0512e2)",
        # "pk(0332647ac7f24148b610ed9643abfec2e72f684cbab27c71b6b044ea45f450d6c323)",
        # "addr(moUS3P3bFiauE3ettzvsU7djgUEFfZ1f2rxyz)",
        # "addr(1HtwbNKMjCET6ESnUFKJFgaUbMCXpLBdJE)#",
        "raw(0332647ac7f24148b610ed9643abfec2e72f684cbab27c71b6b044ea45f450d6c3)#290",
        " raw(6a0b68656c6c6f20776f726c64)",
    ),
)
def test_invalid_descriptors(descriptor):
    try:
        parsed = parse_raw(descriptor)
    except Exception as err:
        assert True
    else:
        assert False, "invalid descriptor parsed without error"
