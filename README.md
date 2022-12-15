### `#bits`

Bitcoin protocol

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


### TODO

Implement and test basic wallet functionality
- generate JBOK
- generate HD wallet mnemonic
  - Bitcoin for now; naturally can extend to other coins per BIP spec
  - generate new xpub, xprv, and all address types legacy, p2sh segwit, and native segwit

Future:
- zero dependencies
- check wallet balance; needs node
- mine
- sign transactions, i.e. spend
- implement full node, spv node

- lightning


bits createwallet

bits to_bitcoin_address <pubkey>
bits to_bitcoin_address <pem>

### Links

- https://en.bitcoin.it/wiki/Protocol_documentation
- https://karpathy.github.io/2021/06/21/blockchain/
- https://en.bitcoin.it/w/images/en/9/9b/PubKeyToAddr.png
- https://developer.bitcoin.org/devguide/transactions.html
- https://developer.bitcoin.org/reference/transactions.html
- https://en.wikipedia.org/wiki/Base64
- https://en.bitcoinwiki.org/wiki/Base58
- https://github.com/bitcoinbook/bitcoinbook
- https://github.com/jimmysong/programmingbitcoin
- https://developers.ledger.com/docs/nano-app/psd-applications/
- https://github.com/trezor/python-mnemonic
- https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
- https://en.bitcoin.it/wiki/OP_CHECKSIG
- http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html

__SegWit__

- https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0145.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

__TapRoot__

- https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

### Notes

Notes and (re/para)phrasing from Programming Bitcoin, Jimmy Song
https://github.com/jimmysong/programmingbitcoin

Ch1

- https://en.wikipedia.org/wiki/Set_(mathematics)
- https://en.wikipedia.org/wiki/Group_(mathematics)
- https://en.wikipedia.org/wiki/Field_(mathematics)
- https://en.wikipedia.org/wiki/Finite_field
- https://en.wikipedia.org/wiki/Modular_arithmetic
- https://en.wikipedia.org/wiki/Fermat's_little_theorem

Finite Fields (Galois field) are have the following properties

1. Closed: if a and b are in the set, a+b and a*b are in the set
2. Additive Identity: 0 exists and has the property a + 0 = a
3. Multiplicative Identity: 1 exists and has the propert a * 1 = a
4. Additive Inverse: If a is in the set, -a is in the set, defined as the value in which
    a + (-a) = 0 
5. Multiplicative Inverse: If a is in the set (and is not 0), a^-1 is in the set
    and is defined as the value in which a * (a^-1) = 1


Let `p` be the order of the Finite Field set (how big the set is)

F_p = set([0, 1, 2, ..., p-1])

??finite field elements in general need not be integers, and p is, strictly speaking, the number of elements

"it turns out that fields must have an order that is a power of a prime, and that the finite fields whose order is prime are the ones we’re interested in"
JT: The set of integers, with order p, where p is prime, turns out to be a (finite) field
    by using modular arithmetic


Fermat's little thereom essentially states

(n**(p-1))%p = 1 where p is prime (and n > 0 ?)

Ch2
...

Ch3
...



TODO
- [x] der decoder
- [x] get public key and private key
- [x] ecmath get pubkey coords from private key
- [x] ecmath get pubkey coord from compressed public key
- [x] support wif
- [x] remove base58 dependency (reimplement functions)
- [ ] add signing operations to ecmath or depend on opessl, remove python-ecdsa dependency
- [ ] implement basic wallet functionality (jbok, hd)
- [ ] implement node, full/spv
- [ ] implement miner

- https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/
- https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
- https://crypto.stanford.edu/~dabo/cs255/syllabus.html
- https://crypto.stanford.edu/~dabo/courses/OnlineCrypto/

- https://github.com/trezor/python-mnemonic
- https://github.com/keis/base58
- https://digitalbazaar.github.io/base58-spec
- https://en.bitcoinwiki.org/wiki/Base58
- https://en.bitcoin.it/wiki/Base58Check_encoding
