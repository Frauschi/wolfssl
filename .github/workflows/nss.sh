#!/usr/bin/env bash
#
# wolfSSL <-> NSS interoperability tests.
#
# Runs every combination of {wolfSSL, NSS} acting as server and client, for
# both TLS 1.3 and DTLS 1.3, and for each of those a classical (ECDHE) and a
# post-quantum ML-KEM hybrid key exchange.  Forcing the ML-KEM hybrid group on
# both peers is what produces an oversized (DTLS: fragmented) ClientHello, which
# is the interop edge case we most want to exercise.
#
# Expected layout of the current working directory:
#   ./dist/Debug/bin/   NSS command line tools (certutil, tstclnt, selfserv, ...)
#   ./wolfssl/          wolfSSL source tree, already built (examples/*)
#
# NSS tool roles:
#   - NSS TLS  server : selfserv          (selfserv has no DTLS support)
#   - NSS DTLS server : tstclnt -P server (tstclnt can bind/listen for DTLS)
#   - NSS client      : tstclnt           (-P client for DTLS)
#
# Group naming: wolfSSL "X25519MLKEM768" == NSS "mlkem768x25519" (same IANA id).

set -u
set -x

NSS_BIN=./dist/Debug/bin
WOLF=wolfssl
PORT=4433
FAIL=0
NSS_NICK=   # nickname of the NSS server identity; derived after import below

# Make the NSS tools load the freshly built shared libraries rather than any
# (possibly older, ABI-incompatible) system libnss3.
export LD_LIBRARY_PATH="$(pwd)/dist/Debug/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

cleanup() { kill "$(jobs -p)" 2>/dev/null || true; }
trap cleanup EXIT

die() { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# NSS database + identities
# ---------------------------------------------------------------------------
rm -rf nssdb
mkdir nssdb
$NSS_BIN/certutil -d nssdb -N --empty-password \
    || die "certutil -N (create NSS db) failed"

# NSS as client: trust the wolfSSL server's cert (server-localhost.pem, which
# the wolfSSL server presents).
$NSS_BIN/certutil -d nssdb -A -a -i $WOLF/certs/test/server-localhost.pem \
    -t 'TC,C,C' -n 'wolf localhost' \
    || die "certutil -A (import trust cert) failed"

# NSS as server (selfserv / tstclnt -P server) needs a cert *and* private key.
# wolfSSL ships a ready-made PKCS#12 (cert + key, password "wolfSSL test") whose
# legacy PBE NSS's pk12util accepts directly -- no openssl needed. The connecting
# wolfSSL client runs with -d (no peer verification), so this identity being a
# different cert than the one above is fine.
$NSS_BIN/pk12util -i $WOLF/certs/test-servercert.p12 -d nssdb -W 'wolfSSL test' -K '' \
    || die "pk12util (import NSS server identity) failed"

# Show the resulting db (the server identity must have a private key: 'u' flags).
$NSS_BIN/certutil -d nssdb -L
$NSS_BIN/certutil -d nssdb -K

# Derive the server nickname from the imported key rather than hard-coding the
# cert's (CN-derived) nickname, so regenerating test-servercert.p12 doesn't
# silently break the NSS-server cases. certutil -K prints one line per key as
# "<idx> keytype  <hash>  <nickname>"; take everything after the hash.
NSS_NICK=$($NSS_BIN/certutil -d nssdb -K 2>/dev/null \
    | awk '/^</ { sub(/^<[^>]*> +[^ ]+ +[^ ]+ +/, ""); print; exit }')
if [ -z "$NSS_NICK" ]; then
    echo "ERROR: could not determine NSS server nickname from db" >&2
    exit 1
fi
echo "NSS server nickname: '$NSS_NICK'"

echo "Hello from the interop peer" > /tmp/in

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Wait until a server's log shows it is ready. Used for the wolfSSL server,
# which is single-shot (-w, no -i): probing it with a throwaway TCP connection
# would consume its one accept() and break the real handshake.
wait_log() {
    local f=$1 re=$2 i
    for i in $(seq 1 100); do
        [ -f "$f" ] && grep -qiE "$re" "$f" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# Wait until something is accepting TCP connections on $1. Safe only for a
# looping server (selfserv) that tolerates the throwaway probe connection.
wait_tcp() {
    local p=$1 i
    for i in $(seq 1 100); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
            exec 3>&- 3<&-
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# Wait until a socket is bound on a port by reading the kernel socket table
# (ss), without opening a connection. This is the only readiness signal for a
# DTLS (UDP) server: there is no listen/accept state to probe, and the wolfSSL
# DTLS server prints no startup banner. Works for a single-shot server too,
# since ss never consumes an accept(). Usage: wait_port <tcp|udp> <port>
wait_port() {
    local proto=$1 port=$2 i flag
    [ "$proto" = udp ] && flag=-uln || flag=-tln
    for i in $(seq 1 100); do
        ss "$flag" 2>/dev/null | grep -qE "[:.]$port[[:space:]]" && return 0
        sleep 0.1
    done
    return 1
}

# run_case <wolf|nss> <tls|dtls> <label> <wolf_pqc|-> <nss_groups> [nss_expect]
#   arg1: which library is the SERVER (the other is the client)
#   arg3: case label; anything matching mlkem* asserts the hybrid was negotiated
#   arg4: wolfSSL --pqc argument, or "-" for classical
#   arg5: NSS -I named group list (comma separated)
#   arg6: NSS name of the group expected to be negotiated. Only needed when arg5
#         lists more than one group; defaults to arg5.
run_case() {
    local srv=$1 proto=$2 label=$3 wpqc=$4 ngrp=$5 nexp=${6:-$5}
    PORT=$((PORT + 1))
    local tag="${srv}server_${proto}_${label}"
    local slog="/tmp/server_${tag}.log"
    local clog="/tmp/client_${tag}.log"
    # Start from empty logs so the DTLS-server reply gate never matches a marker
    # left over from a previous run of this script.
    : > "$slog"; : > "$clog"
    local pqc="" wolf_u="" wolf_stateful=""
    [ "$wpqc" != "-" ] && pqc="--pqc $wpqc"
    if [ "$proto" = dtls ]; then
        wolf_u="-u"
        # NSS fragments its ML-KEM ClientHello and orders the large key_share
        # ahead of the cookie extension, so the cookie is not in the first
        # fragment. A default (stateless) wolfSSL DTLS 1.3 server drops such a
        # ClientHello and the handshake stalls on HRR retransmits. The opt-in
        # stateful server reassembles the whole ClientHello (including the first)
        # and validates the cookie on the complete message, which is what makes
        # this interop work. See --enable-dtls13-stateful-server.
        wolf_stateful="--dtls13-stateful-server"
    fi

    echo "===== CASE $tag : server=$srv proto=$proto kex=$label" \
         "wolf=$wpqc nss=$ngrp port=$PORT ====="

    local spid crc=0

    if [ "$srv" = wolf ]; then
        # ---- wolfSSL server + NSS client ----
        # shellcheck disable=SC2086
        env -C $WOLF ./examples/server/server -v 4 -p $PORT $wolf_u -d -w \
            -c certs/test/server-localhost.pem -k certs/server-key.pem $pqc \
            $wolf_stateful > "$slog" 2>&1 &
        spid=$!

        local pflag=""
        if [ "$proto" = tls ]; then
            # Single-shot server: wait on its log, never probe its accept().
            wait_log "$slog" 'listening on port' \
                || echo "WARN: wolfSSL TLS server not ready on $PORT"
        else
            pflag="-P client"
            wait_port udp $PORT \
                || echo "WARN: wolfSSL DTLS server not bound on $PORT"
        fi
        # Use "localhost" (cert CN) so tstclnt's domain check passes; -4 still
        # forces the actual connection over IPv4.
        # shellcheck disable=SC2086
        timeout 30 $NSS_BIN/tstclnt -V tls1.3: $pflag -h localhost -p $PORT \
            -d nssdb -C -4 -I $ngrp -A /tmp/in -v > "$clog" 2>&1
        crc=$?
    else
        # ---- NSS server + wolfSSL client ----
        if [ "$proto" = tls ]; then
            # shellcheck disable=SC2086
            $NSS_BIN/selfserv -d nssdb -n "$NSS_NICK" -p $PORT \
                -V tls1.3:tls1.3 -I $ngrp -w '' > "$slog" 2>&1 &
            spid=$!
            wait_tcp $PORT || echo "WARN: NSS selfserv not ready on $PORT"
        else
            # tstclnt in DTLS server mode does not auto-reply; feed it a line on
            # stdin so it sends application data back to the wolfSSL client, which
            # always performs a write+read exchange. Sending that reply mid
            # handshake would make the wolfSSL client error with APP_DATA_READY,
            # so gate it on the client reporting a completed handshake ("sending
            # GET", emitted right after connect) rather than on a fixed delay; the
            # trailing sleep keeps stdin open so tstclnt is not EOF'd early.
            # tstclnt requires -h even in -P server mode; 127.0.0.1 also pins the
            # listener to IPv4.
            # shellcheck disable=SC2086
            timeout 40 $NSS_BIN/tstclnt -V tls1.3: -P server -h 127.0.0.1 -p $PORT \
                -d nssdb -n "$NSS_NICK" -I $ngrp -4 -w '' > "$slog" 2>&1 < <(
                    for _ in $(seq 1 300); do
                        grep -q 'sending GET' "$clog" 2>/dev/null && break
                        sleep 0.1
                    done
                    printf 'Hello from nss\n'
                    sleep 5
                ) &
            spid=$!
            wait_port udp $PORT \
                || echo "WARN: NSS DTLS server not bound on $PORT"
        fi
        # -g: send an HTTP GET so the peer replies; -d: no peer check (the wolfSSL
        # test CA does not sign these certs). stdbuf line-buffers stdout so the
        # "sending GET" marker reaches $clog immediately -- otherwise the client's
        # block-buffered log would not flush until it exits, which it cannot do
        # until it receives the reply above (deadlock).
        # shellcheck disable=SC2086
        timeout 30 stdbuf -oL env -C $WOLF ./examples/client/client -v 4 \
            -h 127.0.0.1 -p $PORT $wolf_u -d -g $pqc > "$clog" 2>&1
        crc=$?
    fi

    kill "$spid" 2>/dev/null || true
    wait "$spid" 2>/dev/null || true

    if [ $crc -ne 0 ]; then
        echo "!!!! FAILED $tag (client rc=$crc)"
        echo "----- server log ($slog) -----"; cat "$slog" 2>/dev/null || true
        echo "----- client log ($clog) -----"; cat "$clog" 2>/dev/null || true
        FAIL=1
        return 1
    fi

    # Assert the hybrid was actually negotiated. This must match every ML-KEM
    # case (label mlkem, mlkem1024, mlkem1024hrr), hence the glob rather than an
    # exact compare. It is not merely defensive for the HRR case: there NSS is
    # deliberately offered *two* groups (x25519 plus the hybrid), so unlike the
    # other cases a completed handshake does NOT by itself imply the hybrid was
    # used -- without this check that case would still pass having negotiated
    # x25519, never fragmenting a ClientHello and never exercising the stateful
    # server it exists to test.
    #
    # Anchor on the strings each peer prints *after* the handshake with the
    # group it actually negotiated: wolfSSL "SSL curve name is <wolf name>" and
    # NSS "Key Exchange Group: <nss name>". Do NOT match the bare group name --
    # wolfSSL echoes "Using Post-Quantum KEM: <wolf name>" while merely setting
    # up its key share, before any handshake, so a bare match would pass even on
    # a downgrade. $nexp is the NSS name of the group we expect to win, which
    # for multi-group cases is not the whole -I list.
    case "$label" in
    mlkem*)
        if ! grep -qiE "SSL curve name is $wpqc|Key Exchange Group: $nexp" \
                "$slog" "$clog"; then
            echo "!!!! $tag handshake succeeded but the expected ML-KEM group" \
                 "($wpqc / $nexp) is not in the logs"
            echo "----- server log -----"; cat "$slog" 2>/dev/null || true
            echo "----- client log -----"; cat "$clog" 2>/dev/null || true
            FAIL=1
            return 1
        fi
        ;;
    esac

    echo "++++ PASSED $tag"
    return 0
}

# ---------------------------------------------------------------------------
# Test matrix: {wolf,nss} server x {tls,dtls} x {classical, ML-KEM hybrid}
# ---------------------------------------------------------------------------
W_PQC=X25519MLKEM768       # wolfSSL group name
N_PQC=mlkem768x25519       # NSS group name (same IANA code point)

for srv in wolf nss; do
    for proto in tls dtls; do
        run_case "$srv" "$proto" classical -       x25519   || true
        run_case "$srv" "$proto" mlkem     "$W_PQC" "$N_PQC" || true
    done
done

# ---------------------------------------------------------------------------
# DTLS-only: the largest ML-KEM hybrid. Its key share alone overflows a single
# datagram, so the *first* ClientHello is already fragmented -- the case that
# needs the stateful DTLS 1.3 server. NSS supports this group as
# "secp384r1mlkem1024" (IANA 4589).
# ---------------------------------------------------------------------------
W_PQC1024=SecP384r1MLKEM1024
N_PQC1024=secp384r1mlkem1024

run_case wolf dtls mlkem1024 "$W_PQC1024" "$N_PQC1024" || true
run_case nss  dtls mlkem1024 "$W_PQC1024" "$N_PQC1024" || true

# HelloRetryRequest path: NSS offers x25519 first (and sends only that key
# share) but also advertises the big hybrid, while the wolfSSL server accepts
# only the hybrid. The server therefore answers the small first ClientHello with
# an HRR carrying a cookie, and NSS's *second* ClientHello is both fragmented and
# carries the cookie behind the large key_share -- i.e. the cookie is not in the
# first fragment. This is the case a stateless server cannot reassemble.
run_case wolf dtls mlkem1024hrr "$W_PQC1024" "x25519,$N_PQC1024" "$N_PQC1024" || true

if [ $FAIL -ne 0 ]; then
    echo "============================================"
    echo "wolfSSL <-> NSS interop: FAILURES (see above)"
    echo "============================================"
    exit 1
fi

echo "==================================="
echo "wolfSSL <-> NSS interop: ALL PASSED"
echo "==================================="
