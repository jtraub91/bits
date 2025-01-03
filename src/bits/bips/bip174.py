"""
https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki

<psbt> := <magic> <global-map> <input-map>* <output-map>*
<magic> := 0x70 0x73 0x62 0x74 0xFF
<global-map> := <keypair>* 0x00
<input-map> := <keypair>* 0x00
<output-map> := <keypair>* 0x00
<keypair> := <key> <value>
<key> := <keylen> <keytype> <keydata>
<value> := <valuelen> <valuedata>
"""

MAGIC = b"psbt\xff"
