#!/usr/bin/env bash
set -euo pipefail

BASE=pki
ROOT=$BASE/root
INT=$BASE/intermediate
EE=$BASE/end-entities

mkdir -p $ROOT/{certs,crl,newcerts,private} \
         $INT/{certs,crl,newcerts,private,csr} \
         $EE/{certs,csr,keys}
touch $ROOT/index.txt $INT/index.txt
echo 1000 > $ROOT/serial
echo 1000 > $ROOT/crlnumber
echo 2000 > $INT/serial
echo 2000 > $INT/crlnumber
chmod 700 $ROOT/private $INT/private $EE/keys

# Write configs (same as provided earlier but inline truncated for brevity)
cat > $ROOT/openssl.cnf <<'EOF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir=.
certs=$dir/certs
crl_dir=$dir/crl
new_certs_dir=$dir/newcerts
database=$dir/index.txt
serial=$dir/serial
crlnumber=$dir/crlnumber
certificate=$dir/certs/root-ca.pem
private_key=$dir/private/root-ca.key.pem
default_md=sha256
default_days=9125
unique_subject=no
policy=policy_strict
crl_extensions=crl_ext
[ policy_strict ]
commonName = supplied
[ req ]
default_md=sha256
distinguished_name=req_dn
string_mask=utf8only
x509_extensions=v3_root_ca
prompt=no
[ req_dn ]
CN=ivan.ca.example.com
[ v3_root_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
basicConstraints=critical,CA:true,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
[ v3_intermediate_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
[ crl_ext ]
authorityKeyIdentifier=keyid:always
EOF

cat > $INT/openssl.cnf <<'EOF'
[ ca ]
default_ca=CA_default
[ CA_default ]
dir=.
certs=$dir/certs
crl_dir=$dir/crl
new_certs_dir=$dir/newcerts
database=$dir/index.txt
serial=$dir/serial
crlnumber=$dir/crlnumber
certificate=$dir/certs/intermediate-ca.pem
private_key=$dir/private/intermediate-ca.key.pem
default_md=sha256
default_days=3650
unique_subject=no
policy=policy_loose
crl_extensions=crl_ext
[ policy_loose ]
commonName = supplied
[ req ]
default_md=sha256
distinguished_name=req_dn
string_mask=utf8only
x509_extensions=v3_intermediate_ca
prompt=no
[ req_dn ]
CN=trent.interm.example.com
[ v3_intermediate_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
[ ee_server_client ]
basicConstraints=critical,CA:false
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=@alt_names
[ ee_code_signing ]
basicConstraints=critical,CA:false
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
[ crl_ext ]
authorityKeyIdentifier=keyid:always
[ alt_names ]
DNS.1=bob.users.example.com
EOF

# Root key & cert
cd $ROOT
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -pkeyopt ec_param_enc:named_curve -out private/root-ca.key.pem
chmod 600 private/root-ca.key.pem
openssl req -config openssl.cnf -new -x509 -days 9125 -sha256 -key private/root-ca.key.pem -extensions v3_root_ca -out certs/root-ca.pem

# Intermediate key & CSR
cd ../intermediate
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -pkeyopt ec_param_enc:named_curve -out private/intermediate-ca.key.pem
chmod 600 private/intermediate-ca.key.pem
openssl req -config openssl.cnf -new -key private/intermediate-ca.key.pem -out csr/intermediate-ca.csr.pem

# Sign intermediate with root
cd ../root
openssl ca -batch -config openssl.cnf -in ../intermediate/csr/intermediate-ca.csr.pem -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -out ../intermediate/certs/intermediate-ca.pem
cat ../intermediate/certs/intermediate-ca.pem certs/root-ca.pem > ../intermediate/certs/ca-chain.pem

# End-entity key (P-256) & CSR
cd ../intermediate
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -out ../end-entities/keys/bob.users.example.com.key.pem
chmod 600 ../end-entities/keys/bob.users.example.com.key.pem
openssl req -new -sha256 -key ../end-entities/keys/bob.users.example.com.key.pem -out ../end-entities/csr/bob.users.example.com.csr.pem -subj "/CN=bob.users.example.com"

# SAN override file
cat > ee_san.cnf <<EOF
[ ee_server_client ]
basicConstraints=critical,CA:false
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:bob.users.example.com
EOF

# Sign end-entity (server+client)
openssl ca -batch -config openssl.cnf -in ../end-entities/csr/bob.users.example.com.csr.pem -extensions ee_server_client -extfile ee_san.cnf -days 365 -notext -md sha256 -out ../end-entities/certs/bob.users.example.com.cert.pem

# Fullchain (server cert + intermediate)
cat ../end-entities/certs/bob.users.example.com.cert.pem certs/intermediate-ca.pem > ../end-entities/certs/bob.users.example.com.fullchain.pem
echo "Done. Root: $ROOT/certs/root-ca.pem, Intermediate: $INT/certs/intermediate-ca.pem, End-entity: $EE/certs/bob.users.example.com.cert.pem"

