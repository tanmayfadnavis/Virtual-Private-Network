#!/bin/bash

cp /usr/lib/ssl/openssl.cnf .
chmod 755 ./openssl.cnf

dir="./demoCA"
certs=$dir/certs # Where the issued certs are kept
crl_dir=$dir/crl # Where the issued crl are kept
new_certs_dir=$dir/newcerts # default place for new certs.
database=$dir/index.txt # database index file.
serial=$dir/serial # The current serial number

mkdir -p $certs
mkdir -p $crl_dir
mkdir -p $new_certs_dir

touch $database

echo 1000 > $serial

echo "Now generating CA certificate.."
openssl req -new -x509 -keyout ca.key -out ca.crt -config openssl.cnf

echo "Now generating CSR.."
openssl genrsa -des3 -out server.key 1024
openssl req -new -key server.key -out server.csr -config openssl.cnf

echo "Now sign the certificate..."
openssl ca -in server.csr -out server.crt -cert ca.crt -keyfile ca.key -config openssl.cnf
