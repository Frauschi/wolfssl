#!/usr/bin/env bash

# Generate SLH-DSA certificate chain using OpenSSL 3.5+
# Pattern follows certs/ed25519/gen-ed25519-certs.sh

OPENSSL=${OPENSSL:-openssl}
ALG="SLH-DSA-SHAKE-128f"
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

check_result(){
    if [ $1 -ne 0 ]; then
        echo "Failed at \"$2\", Abort"
        exit 1
    else
        echo "Step Succeeded!"
    fi
}

# Check OpenSSL supports SLH-DSA
$OPENSSL genpkey -algorithm $ALG -out /dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    echo "OpenSSL does not support $ALG"
    echo "Skipping SLH-DSA certificate generation (need OpenSSL 3.5+)"
    exit 0
fi

echo "Using algorithm: $ALG"
echo "====================================================================="

############################################################
###### Generate root CA key and self-signed cert ###########
############################################################
echo "Generating root-slhdsa private key"
$OPENSSL genpkey -algorithm $ALG -out root-slhdsa-priv.pem
check_result $? "Generate root key"

$OPENSSL pkey -in root-slhdsa-priv.pem -pubout -out root-slhdsa-key.pem
check_result $? "Extract root public key"

echo "Generating self-signed root-slhdsa.pem"
echo -e "US\nMontana\nBozeman\nwolfSSL_SLH-DSA\nRoot-SLH-DSA\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | \
$OPENSSL req -new -key root-slhdsa-priv.pem -nodes -out root-slhdsa.csr
check_result $? "Generate root CSR"

$OPENSSL x509 -req -in root-slhdsa.csr -days 3650 \
    -extensions v3_ca \
    -extfile <(printf "[v3_ca]\nbasicConstraints=critical,CA:TRUE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\nkeyUsage=critical,keyCertSign,cRLSign\n") \
    -signkey root-slhdsa-priv.pem -out root-slhdsa.pem
check_result $? "Generate root certificate"
rm -f root-slhdsa.csr

$OPENSSL x509 -in root-slhdsa.pem -outform DER -out root-slhdsa.der
check_result $? "Convert root to DER"

$OPENSSL pkey -in root-slhdsa-priv.pem -outform DER -out root-slhdsa-priv.der
check_result $? "Convert root key to DER"

echo "---------------------------------------------------------------------"

############################################################
###### Generate CA key and cert signed by root #############
############################################################
echo "Generating ca-slhdsa private key"
$OPENSSL genpkey -algorithm $ALG -out ca-slhdsa-priv.pem
check_result $? "Generate CA key"

$OPENSSL pkey -in ca-slhdsa-priv.pem -pubout -out ca-slhdsa-key.pem
check_result $? "Extract CA public key"

echo "Generating ca-slhdsa.pem signed by root"
echo -e "US\nMontana\nBozeman\nwolfSSL_SLH-DSA\nCA-SLH-DSA\nwww.wolfssl.com\ninfo@wolfssl.com\n\n\n\n" | \
$OPENSSL req -new -key ca-slhdsa-priv.pem -nodes -out ca-slhdsa.csr
check_result $? "Generate CA CSR"

$OPENSSL x509 -req -in ca-slhdsa.csr -days 3650 \
    -extensions v3_ca \
    -extfile <(printf "[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\nkeyUsage=critical,keyCertSign,cRLSign\n") \
    -CA root-slhdsa.pem -CAkey root-slhdsa-priv.pem -set_serial 01 \
    -out ca-slhdsa.pem
check_result $? "Generate CA certificate"
rm -f ca-slhdsa.csr

$OPENSSL x509 -in ca-slhdsa.pem -outform DER -out ca-slhdsa.der
check_result $? "Convert CA to DER"

$OPENSSL pkey -in ca-slhdsa-priv.pem -outform DER -out ca-slhdsa-priv.der
check_result $? "Convert CA key to DER"

echo "---------------------------------------------------------------------"

############################################################
###### Generate server key and cert signed by CA ###########
############################################################
echo "Generating server-slhdsa private key"
$OPENSSL genpkey -algorithm $ALG -out server-slhdsa-priv.pem
check_result $? "Generate server key"

$OPENSSL pkey -in server-slhdsa-priv.pem -pubout -out server-slhdsa-key.pem
check_result $? "Extract server public key"

echo "Generating server-slhdsa.pem signed by CA"
echo -e "US\nMontana\nBozeman\nwolfSSL_SLH-DSA\nServer-SLH-DSA\nwww.wolfssl.com\ninfo@wolfssl.com\n\n\n\n" | \
$OPENSSL req -new -key server-slhdsa-priv.pem -nodes -out server-slhdsa.csr
check_result $? "Generate server CSR"

$OPENSSL x509 -req -in server-slhdsa.csr -days 3650 \
    -extensions v3_server \
    -extfile <(printf "[v3_server]\nbasicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n") \
    -CA ca-slhdsa.pem -CAkey ca-slhdsa-priv.pem -set_serial 01 \
    -out server-slhdsa-cert.pem
check_result $? "Generate server certificate"
rm -f server-slhdsa.csr

$OPENSSL x509 -in server-slhdsa-cert.pem -outform DER -out server-slhdsa.der
check_result $? "Convert server cert to DER"

$OPENSSL pkey -in server-slhdsa-priv.pem -outform DER -out server-slhdsa-priv.der
check_result $? "Convert server key to DER"

# Create full chain: server cert + CA cert
cat server-slhdsa-cert.pem ca-slhdsa.pem > server-slhdsa.pem
check_result $? "Create server chain"

echo "---------------------------------------------------------------------"

############################################################
###### Generate client key and cert signed by CA ###########
############################################################
echo "Generating client-slhdsa private key"
$OPENSSL genpkey -algorithm $ALG -out client-slhdsa-priv.pem
check_result $? "Generate client key"

$OPENSSL pkey -in client-slhdsa-priv.pem -pubout -out client-slhdsa-key.pem
check_result $? "Extract client public key"

echo "Generating client-slhdsa.pem signed by CA"
echo -e "US\nMontana\nBozeman\nwolfSSL_SLH-DSA\nClient-SLH-DSA\nwww.wolfssl.com\ninfo@wolfssl.com\n\n\n\n" | \
$OPENSSL req -new -key client-slhdsa-priv.pem -nodes -out client-slhdsa.csr
check_result $? "Generate client CSR"

$OPENSSL x509 -req -in client-slhdsa.csr -days 3650 \
    -extensions v3_client \
    -extfile <(printf "[v3_client]\nbasicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n") \
    -CA ca-slhdsa.pem -CAkey ca-slhdsa-priv.pem -set_serial 02 \
    -out client-slhdsa-cert.pem
check_result $? "Generate client certificate"
rm -f client-slhdsa.csr

$OPENSSL x509 -in client-slhdsa-cert.pem -outform DER -out client-slhdsa.der
check_result $? "Convert client cert to DER"

$OPENSSL pkey -in client-slhdsa-priv.pem -outform DER -out client-slhdsa-priv.der
check_result $? "Convert client key to DER"

# Create full chain: client cert + CA cert
cat client-slhdsa-cert.pem ca-slhdsa.pem > client-slhdsa.pem
check_result $? "Create client chain"

echo "---------------------------------------------------------------------"

############################################################
###### Verify chain ########################################
############################################################
echo "Verifying certificate chain"
cat root-slhdsa.pem ca-slhdsa.pem > ca-chain.pem
$OPENSSL verify -CAfile root-slhdsa.pem ca-slhdsa.pem
check_result $? "Verify CA cert"
$OPENSSL verify -CAfile ca-chain.pem server-slhdsa-cert.pem
check_result $? "Verify server cert"
$OPENSSL verify -CAfile ca-chain.pem client-slhdsa-cert.pem
check_result $? "Verify client cert"
rm -f ca-chain.pem

echo ""
echo "====================================================================="
echo "SLH-DSA certificate chain generated successfully!"
echo "  Root CA:  root-slhdsa.pem / root-slhdsa.der"
echo "  CA:       ca-slhdsa.pem / ca-slhdsa.der"
echo "  Server:   server-slhdsa-cert.pem / server-slhdsa.der (chain: server-slhdsa.pem)"
echo "  Client:   client-slhdsa-cert.pem / client-slhdsa.der (chain: client-slhdsa.pem)"
echo "====================================================================="
