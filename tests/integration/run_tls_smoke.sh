#!/usr/bin/env bash
# gdb-mcp HTTP transport TLS/mTLS end-to-end smoke (E4 closure).
#
# Runs on Git Bash (Windows) or inside WSL:
#   bash tests/integration/run_tls_smoke.sh
#
# Closes the "mTLS needs a real certificate environment" gap with a
# throwaway PKI (CA + server + client certs, valid 2 days):
#   [1] plaintext baseline - plain HTTP transport answers
#   [2] TLS                - https with CA trust passes; plaintext http
#                            and untrusted https both fail
#   [3] mTLS               - client cert required: with passes, without
#                            fails the TLS handshake
#   [4] tokens over mTLS   - no/wrong bearer -> 403; observer and
#                            controller bearers pass the middleware
# No gdb is involved: this exercises the transport hardening layer only.
#
# The HTTPS client side is python stdlib (ssl + urllib), not curl: the
# mingw64 curl shipped with Git for Windows uses schannel, which cannot
# load PEM client certificates and enforces revocation checks.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
PYTHON="${GDB_MCP_TEST_PYTHON:-$(command -v python || command -v python3)}"
PLUGIN_PORT=39419
MCP_PORT=39420
WORK="$(mktemp -d)"
SERVER_PID=""

#: Git Bash /tmp is MSYS-only; Windows python needs a C:/... form
WORK_P="$(cygpath -m "$WORK" 2>/dev/null || echo "$WORK")"
#: ...and MSYS must not rewrite openssl's -subj "/CN=..." into a path
export MSYS2_ARG_CONV_EXCL='/CN'

cleanup() {
    if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "[tls-smoke] FAIL: $*" >&2; exit 1; }

#: prints "HTTP <code>" when the server answered (any code, incl. 403),
#: or "FAIL <reason>" when the connection/TLS layer broke.
probe() {  # args: url [ca] [cert] [key] [bearer]
    "$PYTHON" "$WORK/probe.py" "$@"
}

cat >"$WORK/probe.py" <<'PYEOF'
import ssl
import sys
import urllib.error
import urllib.request

argv = sys.argv[1:] + [""] * (5 - len(sys.argv[1:]))
url, ca, cert, key, bearer = (value or None for value in argv[:5])
context = ssl.create_default_context(cafile=ca)
if cert:
    context.load_cert_chain(cert, key)
headers = {"User-Agent": "tls-smoke"}
if bearer:
    headers["Authorization"] = "Bearer " + bearer
request = urllib.request.Request(url, headers=headers)
try:
    with urllib.request.urlopen(request, timeout=5, context=context) as resp:
        print("HTTP %d" % resp.status)
except urllib.error.HTTPError as exc:
    print("HTTP %d" % exc.code)
except Exception as exc:  # TLS handshake refused, wrong CA, no client cert
    print("FAIL %s" % type(exc).__name__)
PYEOF

start_server() {  # args: extra gdb-mcp flags
    PYTHONPATH="$ROOT/src" "$PYTHON" -m gdb_mcp \
        --http --mcp-host 127.0.0.1 --mcp-port "$MCP_PORT" \
        --port "$PLUGIN_PORT" --log-dir "$WORK_P/logs" \
        "$@" >"$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 50); do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            fail "server exited early; log:"$'\n'"$(tail -20 "$WORK/server.log")"
        fi
        answer=$(probe "http://127.0.0.1:$MCP_PORT/mcp" 2>/dev/null || true)
        if [ "${answer#HTTP}" = "$answer" ]; then
            # TLS variants: plaintext gets RemoteDisconnected (correct);
            # readiness = an answer over https with the test PKI
            answer=$(probe "https://127.0.0.1:$MCP_PORT/mcp"                 "$WORK_P/ca.crt" "$WORK_P/client.crt" "$WORK_P/client.key"                 2>/dev/null || true)
        fi
        [ "${answer#HTTP}" != "$answer" ] && return 0
        sleep 0.2
    done
    fail "server did not come up; log:"$'\n'"$(tail -20 "$WORK/server.log")"
}

stop_server() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
}

echo "[tls-smoke] workdir $WORK"

echo "[1/5] throwaway PKI (CA / server / client)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" \
    -out "$WORK/ca.crt" -days 2 -subj "/CN=gdb-mcp-test-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/server.key" \
    -out "$WORK/server.csr" -subj "/CN=localhost" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' >"$WORK/san.ext"
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.crt" \
    -CAkey "$WORK/ca.key" -CAcreateserial -out "$WORK/server.crt" \
    -days 2 -extfile "$WORK/san.ext" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/client.key" \
    -out "$WORK/client.csr" -subj "/CN=gdb-mcp-test-client" >/dev/null 2>&1
openssl x509 -req -in "$WORK/client.csr" -CA "$WORK/ca.crt" \
    -CAkey "$WORK/ca.key" -CAcreateserial -out "$WORK/client.crt" \
    -days 2 >/dev/null 2>&1
test -s "$WORK/server.crt" && test -s "$WORK/client.crt" \
    || fail "PKI generation produced nothing"

echo "[2/5] baseline: plaintext HTTP transport"
start_server
answer=$(probe "http://127.0.0.1:$MCP_PORT/mcp")
[ "${answer#HTTP}" != "$answer" ] || fail "plaintext transport did not answer"
echo "      plain GET /mcp -> $answer (middleware passed)"
stop_server

echo "[3/5] TLS: server certificate only"
start_server --mcp-tls-cert "$WORK_P/server.crt" \
    --mcp-tls-key "$WORK_P/server.key"
answer=$(probe "https://127.0.0.1:$MCP_PORT/mcp" "$WORK_P/ca.crt")
[ "${answer#HTTP}" != "$answer" ] || fail "https with CA trust failed"
echo "      https + CA trust -> $answer"
answer=$(probe "http://127.0.0.1:$MCP_PORT/mcp")
[ "${answer#FAIL}" != "$answer" ] || fail "plaintext http unexpectedly worked"
echo "      plaintext http against TLS server -> $answer (expected)"
answer=$(probe "https://127.0.0.1:$MCP_PORT/mcp")
[ "${answer#FAIL}" != "$answer" ] || fail "untrusted https unexpectedly worked"
echo "      https without CA trust -> $answer (expected)"
stop_server

echo "[4/5] mTLS: client certificate required"
start_server --mcp-tls-cert "$WORK_P/server.crt" \
    --mcp-tls-key "$WORK_P/server.key" --mcp-tls-client-ca "$WORK_P/ca.crt"
answer=$(probe "https://127.0.0.1:$MCP_PORT/mcp" "$WORK_P/ca.crt" \
    "$WORK_P/client.crt" "$WORK_P/client.key")
[ "${answer#HTTP}" != "$answer" ] || fail "mTLS with client cert failed"
echo "      https + client cert -> $answer"
answer=$(probe "https://127.0.0.1:$MCP_PORT/mcp" "$WORK_P/ca.crt")
[ "${answer#FAIL}" != "$answer" ] || fail "no client cert unexpectedly worked"
echo "      https without client cert -> $answer (handshake rejected, expected)"
stop_server

echo "[5/5] bearer tokens enforced over mTLS"
start_server --mcp-tls-cert "$WORK_P/server.crt" \
    --mcp-tls-key "$WORK_P/server.key" --mcp-tls-client-ca "$WORK_P/ca.crt" \
    --token controller-secret --observer-token observer-secret
mtls() {  # bearer value or "" ; prints probe answer
    probe "https://127.0.0.1:$MCP_PORT/mcp" "$WORK_P/ca.crt" \
        "$WORK_P/client.crt" "$WORK_P/client.key" "$1"
}
answer=$(mtls "")
[ "$answer" = "HTTP 403" ] || fail "missing bearer gave '$answer', want HTTP 403"
echo "      no bearer       -> $answer"
answer=$(mtls "wrong-token")
[ "$answer" = "HTTP 403" ] || fail "wrong bearer gave '$answer', want HTTP 403"
echo "      wrong bearer    -> $answer"
answer=$(mtls "observer-secret")
[ "${answer#HTTP}" != "$answer" ] && [ "$answer" != "HTTP 403" ] \
    || fail "observer bearer rejected: '$answer'"
echo "      observer bearer -> $answer (middleware passed)"
answer=$(mtls "controller-secret")
[ "${answer#HTTP}" != "$answer" ] && [ "$answer" != "HTTP 403" ] \
    || fail "controller bearer rejected: '$answer'"
echo "      controller      -> $answer (middleware passed)"
stop_server

echo "[tls-smoke] OK: plaintext / TLS / mTLS / tokens-over-mTLS all verified"
