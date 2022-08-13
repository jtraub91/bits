#!/bin/bash
# on airgap,
openssl ecparam -name secp256k1 -genkey -noout -out keys.pem
openssl ec -in keys.pem -pubout -out public.pem -conv_form compressed
cat public.pem
# copy public key to online machine
