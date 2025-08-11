#!/usr/bin/env bash
#
# ivan.ca.example.com   PKI infrastructure setup script
#   |
#   +-trent.
#   

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

BASE=pki
ROOT=${BASE}/root
INT=${BASE}/intermediate
EE=${BASE}/end-entities

echo $SCRIPT_DIR

main() {
    # Create root CA
    create_ca  "ivan"
    # Create intermediate CA
    create_int "ivan" "trent"
    create_int "ivan" "pat"
    # Create end-entities
    create_ee "trent" "bob"
    create_ee "trent" "alice"
    create_ee "pat" "charlie"
}

create_ca() {
    local name="$1"

    local work_dir="${SCRIPT_DIR}/${ROOT}/${name}"

    mkdir -p ${work_dir}/{certs,crl,newcerts,private}
    touch ${work_dir}/index.txt
    echo 1000 > ${work_dir}/serial
    echo 1000 > ${work_dir}/crlnumber

    chmod 700 ${work_dir}/private

    cat > ${work_dir}/openssl.cnf << EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir=.
certs=\$dir/certs
crl_dir=\$dir/crl
new_certs_dir=\$dir/newcerts
database=\$dir/index.txt
serial=\$dir/serial
crlnumber=\$dir/crlnumber
certificate=\$dir/certs/root-ca.pem
private_key=\$dir/private/root-ca.pem
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
CN=${name}.ca.example.com
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

    cd ${work_dir}
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -pkeyopt ec_param_enc:named_curve -out private/root-ca.pem
    chmod 600 private/root-ca.pem
    openssl req -config openssl.cnf -new -x509 -days 9125 -sha256 -key private/root-ca.pem -extensions v3_root_ca -out certs/root-ca.pem
}

create_int() {
    local ca_name="$1"
    local name="$2"

    local work_dir="${SCRIPT_DIR}/${INT}/${name}"
    local ca_dir="${SCRIPT_DIR}/${ROOT}/${ca_name}"

    mkdir -p ${work_dir}/{certs,crl,newcerts,private,csr}
    touch ${work_dir}/index.txt
    echo 2000 > ${work_dir}/serial
    echo 2000 > ${work_dir}/crlnumber

    chmod 700 ${work_dir}/private

cat > ${work_dir}/openssl.cnf << EOF
[ ca ]
default_ca=CA_default
[ CA_default ]
dir=.
certs=\$dir/certs
crl_dir=\$dir/crl
new_certs_dir=\$dir/newcerts
database=\$dir/index.txt
serial=\$dir/serial
crlnumber=\$dir/crlnumber
certificate=\$dir/certs/intermediate-ca.pem
private_key=\$dir/private/intermediate-ca.pem
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
CN=${name}.interm.example.com
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
DNS.1=${name}.ee.example.com
EOF

    cd ${work_dir}
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
        -pkeyopt ec_param_enc:named_curve -out private/intermediate-ca.pem
    chmod 600 private/intermediate-ca.pem
    openssl req -config openssl.cnf -new -key private/intermediate-ca.pem -out csr/intermediate-ca.csr

    # Sign intermediate with root
    cd ${ca_dir}
    openssl ca -batch -config openssl.cnf -in ${work_dir}/csr/intermediate-ca.csr \
        -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -out ${work_dir}/certs/intermediate-ca.pem
    cat ${work_dir}/certs/intermediate-ca.pem certs/root-ca.pem > ${work_dir}/certs/ca-chain.pem
}

create_ee() {
    local int_name="$1"
    local name="$2"

    local work_dir="${SCRIPT_DIR}/${EE}/${name}"
    local int_dir="${SCRIPT_DIR}/${INT}/${int_name}"

    mkdir -p ${work_dir}/{certs,csr,private}

    chmod 700 ${work_dir}/private

    cd ${int_dir}
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
        -pkeyopt ec_param_enc:named_curve -out ${work_dir}/private/${name}.ee.example.com.pem
    chmod 600 ${work_dir}/private/${name}.ee.example.com.pem
    openssl req -new -sha256 -key ${work_dir}/private/${name}.ee.example.com.pem \
        -out ${work_dir}/csr/${name}.ee.example.com.csr -subj "/CN=${name}.ee.example.com"

    # SAN override file
    cat > ee_san.cnf <<EOF
[ ee_server_client ]
basicConstraints=critical,CA:false
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:${name}.ee.example.com
EOF

    # Sign end-entity (server+client)
    openssl ca -batch -config openssl.cnf -in ${work_dir}/csr/${name}.ee.example.com.csr \
        -extensions ee_server_client -extfile ee_san.cnf -days 730 \
        -notext -md sha256 -out ${work_dir}/certs/${name}.ee.example.com.cert.pem

    # Fullchain (server cert + intermediate)
    cat ${work_dir}/certs/${name}.ee.example.com.cert.pem certs/intermediate-ca.pem > ${work_dir}/certs/${name}.ee.example.com.fullchain.cert.pem

    return 0
}

main "$@"