#!/usr/bin/env bash
#
# SLH-DSA TLS 1.3 interoperability test: wolfSSL <-> OpenSSL + oqs-provider.
#
# Exercises the SLH-DSA handshake signature (CertificateVerify) in both
# directions against an independent implementation, per draft-reddy-tls-slhdsa
# (TLS SignatureScheme code points 0x0911-0x091C). The larger 'f' parameter
# sets produce >16KB signatures, so this also exercises fragmented
# CertificateVerify send + reassembly across the two stacks.
#
# OpenSSL < 3.5 has no native SLH-DSA and OpenSSL >= 3.5 does not expose
# SLH-DSA as a TLS signature scheme, while oqs-provider drops SLH-DSA when the
# underlying OpenSSL provides it natively. OpenSSL 3.4 (provider TLS-sigalg
# support, no native SLH-DSA) is therefore the reference peer here, with
# liboqs + oqs-provider supplying the SLH-DSA algorithms and the 0x0911 code
# points that wolfSSL matches.
#
# Prerequisites (built from source, see build steps below):
#   - liboqs (main) built with OQS_USE_OPENSSL=OFF
#   - oqs-provider (main) built against OpenSSL 3.4
#   - OpenSSL 3.4 (shared)
#   - wolfSSL configured with: --enable-tls13 --enable-slhdsa [CFLAGS=-DWOLFSSL_SLHDSA_SHA2]
#
# Build steps (run once; OQS_ROOT defaults to $HOME/oqs-interop):
#   git clone https://github.com/open-quantum-safe/liboqs
#   cmake -S liboqs -B liboqs/build -GNinja -DCMAKE_INSTALL_PREFIX=$OQS_ROOT/local \
#         -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF
#   ninja -C liboqs/build install
#   git clone -b openssl-3.4 https://github.com/openssl/openssl $OQS_ROOT/openssl34
#   (cd $OQS_ROOT/openssl34 && ./Configure --prefix=$OQS_ROOT/ossl34 shared no-docs \
#         -Wl,-rpath,$OQS_ROOT/ossl34/lib64 && make -j"$(nproc)" && make install_sw)
#   git clone https://github.com/open-quantum-safe/oqs-provider
#   cmake -S oqs-provider -B oqs-provider/build -GNinja \
#         -DOPENSSL_ROOT_DIR=$OQS_ROOT/ossl34 \
#         -Dliboqs_DIR=$OQS_ROOT/local/lib/cmake/liboqs
#   ninja -C oqs-provider/build oqsprovider
#
# Usage: run from the wolfSSL source root after `./configure ... && make`.
#   OQS_ROOT=/path/to/oqs-interop ./scripts/slhdsa-oqs-interop.sh

set -u

OQS_ROOT="${OQS_ROOT:-$HOME/oqs-interop}"
OSSL_DIR="${OSSL_DIR:-$OQS_ROOT/ossl34}"
OQS_MODULES="${OQS_MODULES:-$OQS_ROOT/oqs-provider/build/lib}"
OQS_LIBS="${OQS_LIBS:-$OQS_ROOT/local/lib}"
OSSL="$OSSL_DIR/bin/openssl"
PORT="${PORT:-11801}"
WOLF_SRV=./examples/server/server
WOLF_CLI=./examples/client/client
CERTDIR=certs/slhdsa
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; pkill -f "s_server -tls1_3 -accept $PORT" 2>/dev/null' EXIT

# Environment for driving the OpenSSL side with oqs-provider.
osslenv() {
    env LD_LIBRARY_PATH="$OSSL_DIR/lib64:$OQS_LIBS" \
        OPENSSL_MODULES="$OQS_MODULES" \
        OPENSSL_CONF="${OPENSSL_CONF:-/usr/lib/ssl/openssl.cnf}" "$@"
}
# Environment for driving the wolfSSL examples.
wolfenv() { env LD_LIBRARY_PATH=./src/.libs "$@"; }

fail=0
pass() { echo "PASS: $1"; }
fatal() { echo "FAIL: $1"; fail=1; }

[ -x "$OSSL" ] || { echo "OpenSSL 3.4 not found at $OSSL (see build steps)"; exit 1; }
[ -f "$OQS_MODULES/oqsprovider.so" ] || { echo "oqsprovider.so not found (see build steps)"; exit 1; }

echo "wolfSSL:   $(cat wolfssl/version.h 2>/dev/null | grep LIBWOLFSSL_VERSION_STRING | awk '{print $3}' | tr -d '\"')"
echo "OpenSSL:   $(osslenv "$OSSL" version)"
echo "oqs SLH-DSA sig algs: $(osslenv "$OSSL" list -signature-algorithms -provider oqsprovider 2>/dev/null | grep -c slhdsa)"
echo

# ---- Direction A: wolfSSL server signs, OpenSSL+oqs client verifies ----
# param=SLH-DSA scheme name (openssl), cert/key = wolfSSL-generated SLH-DSA leaf
dirA() {
    local name="$1" cert="$2" key="$3" sigalg="$4"
    wolfenv timeout 30 "$WOLF_SRV" -v 4 -c "$cert" -k "$key" -d -p "$PORT" \
        > "$TMP/a_srv.log" 2>&1 &
    local sp=$!; sleep 1
    echo | osslenv timeout 25 "$OSSL" s_client -tls1_3 -connect 127.0.0.1:"$PORT" \
        -CAfile "$cert" -provider oqsprovider -provider default \
        -sigalgs "$sigalg" -verify_return_error > "$TMP/a_cli.log" 2>&1
    wait $sp 2>/dev/null
    if grep -q "Peer signature type: $sigalg" "$TMP/a_cli.log" \
        && grep -q "Verify return code: 0 (ok)" "$TMP/a_cli.log"; then
        pass "A [$name] wolfSSL signs -> OpenSSL+oqs verifies"
    else
        fatal "A [$name] wolfSSL signs -> OpenSSL+oqs verifies"
        tail -3 "$TMP/a_cli.log"; tail -2 "$TMP/a_srv.log"
    fi
}

# ---- Direction B: OpenSSL+oqs server signs, wolfSSL client verifies ----
dirB() {
    local name="$1" sigalg="$2"
    # OpenSSL generates its own SLH-DSA leaf so it can load the private key.
    osslenv "$OSSL" req -x509 -new -newkey "$sigalg" \
        -provider oqsprovider -provider default -nodes \
        -keyout "$TMP/o_key.pem" -out "$TMP/o_cert.pem" \
        -subj "/CN=openssl-$sigalg" -days 365 > "$TMP/b_gen.log" 2>&1
    osslenv timeout 30 "$OSSL" s_server -tls1_3 -accept "$PORT" \
        -provider oqsprovider -provider default \
        -cert "$TMP/o_cert.pem" -key "$TMP/o_key.pem" -naccept 1 -www \
        > "$TMP/b_srv.log" 2>&1 &
    local sp=$!; sleep 1
    wolfenv timeout 25 "$WOLF_CLI" -v 4 -A "$TMP/o_cert.pem" -h 127.0.0.1 -p "$PORT" -g \
        > "$TMP/b_cli.log" 2>&1
    wait $sp 2>/dev/null
    if grep -q "Doing SLH-DSA peer cert verify" "$TMP/b_cli.log" \
        && grep -q "DoTls13CertificateVerify, return 0" "$TMP/b_cli.log"; then
        pass "B [$name] OpenSSL+oqs signs -> wolfSSL verifies"
    else
        fatal "B [$name] OpenSSL+oqs signs -> wolfSSL verifies"
        tail -4 "$TMP/b_cli.log"
    fi
}

# SHAKE-128f: ~17KB signature -> fragmented CertificateVerify (both directions).
if [ -f "$CERTDIR/entity-slhdsa-shake-128f.pem" ]; then
    dirA "SHAKE-128f (fragmented)" \
        "$CERTDIR/entity-slhdsa-shake-128f.pem" \
        "$CERTDIR/entity-slhdsa-shake-128f-priv.pem" slhdsashake128f
fi
dirB "SHAKE-128f (fragmented)" slhdsashake128f

# SHA2-128s: single-record signature; exercises the SHA2 parameter family.
if [ -f "$CERTDIR/root-slhdsa-sha2-128s.pem" ]; then
    dirA "SHA2-128s" \
        "$CERTDIR/root-slhdsa-sha2-128s.pem" \
        "$CERTDIR/root-slhdsa-sha2-128s-priv.pem" slhdsasha2128s
fi

echo
[ $fail -eq 0 ] && echo "All SLH-DSA interop scenarios passed." || echo "Some scenarios FAILED."
exit $fail
