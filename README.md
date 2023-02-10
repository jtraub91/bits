# `bits10001010010101101`

`bits` is a cli tool and pure Python library enabling easy and convenient use for all things Bitcoin

## Highlights

- Generate private key and calculate corresponding public key
- Calculate standard address types (P2PKH, P2SH, Multisig, Segwit)
- Create and sign transactions
- Calculate mnemonic phrase and derive extended keys from seed (per BIP32, BIP39, BIP43, BIP44)
- RPC interface with local `bitcoind` node

## Dependencies

- Python 3.7+

## Installation

```bash
pip install bits
```

v0.1.0 - MVP

v0.2.0

- `sweep` cli command i.e. send all (or fraction) associated with from_addr to  to_addr (optional change_addr)

v1.0.0

- full node
- `scan` cli command
