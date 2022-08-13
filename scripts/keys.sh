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
