### `bits`

_Goals_

  1. Learn crypto protocols
  2. Document specifications (via code and comments)
  3. Provide a practical and secure implementation, minimizing but capitalizing on 3rd party dependencies

_Objectives_

  1. Generate and manage crypto identities
  2. Form transactions, and sign transactions
  3. Use a local / remote RPC node to relay transactions
  4. Check balances
  5. Perform P2P consensus?
  6. Broadcast peer to peer transactions?
  7. Mine?


## Install Bitcoin core

Install Bitcoin core and run a Full Node

## Offline

Generate crypto identity
Sign transactions

## Online

Broadcast transactions to network (via rpc to your full node)


### Demo

>>> from bits.identity import generate_keypair
>>> privkey, pubkey = generate_keypair()

>>> from bits.wallet import HD
>>> new_hd_wallet = HD()
>>> new_hd_wallet.mnemonic
>>> 

>>> from bits.tx import Tx
>>> transaction = Tx(inputs, outputs)

### Description

This library was developed for educational purposes and as a way to self document the Bitcoin protocol.
It intends to provide a python equivalent of the spec, as closely as possible,
avoiding excessive use of covenience shorthands, unless where appropriate.

### Set up bitcoin core full node

TODO

### Set up lightning node

TODO


### Recipes

_create a private key with openssl_

```
openssl ecparam -name secp256k1 -genkey -noout -out <filename>.pem
# pem holds ec params, private, and public key
# openssl ec -help
```


### Philosophy

- use openssl for key and signing operations
- use local Bitcoin core full node for source of truth blockchain info, etc.
- functional before object oriented
