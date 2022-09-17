### `#bits`

```
bits & tricks for Bitcoin
```

## Installation

```
pip install bits
```

## Recommended usage

Generate keys in an offline, airgapped computer (e.g. raspberry pi), write pubkey (only) to paper

_load pubkey bits_

```
from bits.btypes import pubkey_hash, bitcoin_address
from bits.keys import load_pubkey

pk_1 = load_pubkey(b"\x04\x...\x...")
pkh_1 = pubkey_hash(pk_1)
baddr_1 = bitcoin_address(pkh_1)
```

identify utxos (bitcoin rpc)
create raw tx
send tx, via RPC to bitcoin core full node



_Goals_

  1. Learn crypto protocols
  2. Document specifications (via code and comments)
  3. Provide a practical and secure implementation, minimizing but capitalizing on 3rd party dependencies

_Objectives_

  1. Generate and manage crypto identities
  2. Form transactions, and sign transactions
  3. Use a local / remote RPC node to relay transactions and check balances (SPV)
  4. Perform P2P consensus?
  5. Broadcast peer to peer transactions?
  6. Mine?

## Install Bitcoin core

Install Bitcoin core and run a Full Node


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

### Examples

_CLI_

```
$ bits to_bitcoin_address 02ee784d05304ca4e5595ea8bc17c8dd6d613079000f3ee0c2292a57370bafc066
1MXHGHdhGRdZo551ibWMtb7D53LT3GdqtC
```

_createrawtx_ (TODO)

```
$ bits createrawtx --help
```


### Appendix

```
#!/bin/bash

# list openssl ec curves
openssl ecparam -list_curves > /dev/null

# generate private key on Bitcoin secp256k1 curve, to file keys.pem
openssl ecparam -name secp256k1 -genkey -noout -out keys.pem

# get only public key from keys.pem, output to file public.pem
openssl ec -in keys.pem -pubout -out public.pem

# show public key hex
openssl ec -in public.pem -pubin -text -noout

# output public key compressed pem
openssl ec -in public.pem -pubin -conv_form compressed

# "" to file
openssl ec -in keys.pem -pubout -out public.pem -conv_form compressed
cat public.pem

# get hex string from public.pem file
echo $(openssl ec -in public.pem -pubin -text | grep -E "[a-f0-9][a-f0-9]:" | tr -d ' ' | tr -d ':' | tr -d '\n')
```
