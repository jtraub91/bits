import csv

import pytest

from bits.bips import bip340
from bits.ecmath import compute_point

with open("tests/unit/bip340/test-vectors.csv") as csv_file:
    reader = csv.reader(csv_file)
    rows = [row for row in reader]

headers = rows[0]
rows = rows[1:]
vectors = [
    [bytes.fromhex(elem) for elem in vector[1:-2]]
    + [True if vector[-2] == "TRUE" else False]
    for vector in rows
]


@pytest.mark.parametrize("key,pubkey,aux,message,signature,result", vectors)
def test_vectors(
    key: bytes,
    pubkey: bytes,
    aux: bytes,
    message: bytes,
    signature: bytes,
    result: bool,
):
    if key:
        assert (
            bip340.sign(key, message, aux=aux) == signature
        ), "signature does not match expected"

        point = compute_point(key)
        pk = bip340.pubkey(point)
        assert pk == pubkey, "pubkey does not match expected"

    try:
        bip340.verify(pubkey, message, signature)
    except AssertionError:
        assert not result, "verification failed"
    else:
        assert result, "verification succeeded unexpectedly"
