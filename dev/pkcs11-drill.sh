#!/usr/bin/env bash
set -euo pipefail

# Creates only disposable native SoftHSM state; never point this drill at hardware.
cd "$(dirname "$0")/.."
exports=$(scripts/softhsm-dev.sh up)
eval "$exports"
state="${SOFTHSM2_CONF%/*}"
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" || true
  fi
  scripts/softhsm-dev.sh down
}
trap cleanup EXIT
make test-pkcs11
make build-pkcs11
export COSMOSIGNER_BACKEND=pkcs11
binary=./bin/cosmosigner-pkcs11
"$binary" version | grep -q 'pkcs11: true'
"$binary" pubkey

common=(--chain-id pkcs11-drill --node 127.0.0.1:1 --raft-bind 127.0.0.1:0
        --raft-insecure --raft-bootstrap --raft-single-node --raft-data-dir "$state/raft"
        --conn-key "$state/conn.json")
cluster_id=$("$binary" start "${common[@]}" --initialize-only)
"$binary" claim-key --cluster-id "$cluster_id"
"$binary" claim-key --cluster-id "$cluster_id"
if "$binary" claim-key --cluster-id 00000000-0000-4000-8000-000000000001; then
  echo 'mismatched cluster claim unexpectedly succeeded' >&2
  exit 1
fi

# A separate marker exercises the orchestrated claim against the initialized history.
export COSMOSIGNER_PKCS11_BINDING_FILE="$state/start-binding.json"
"$binary" start "${common[@]}" --claim-if-unclaimed --http-addr 127.0.0.1:0 > "$state/start.log" 2>&1 &
pid=$!
ready=false
for _ in {1..100}; do
  if ! kill -0 "$pid" 2>/dev/null; then cat "$state/start.log" >&2; exit 1; fi
  address=$(sed -n 's/.*health endpoints listening.*addr=\(127\.0\.0\.1:[0-9]*\).*/\1/p' "$state/start.log" | head -1)
  if [[ -n "$address" ]] && curl -fsS "http://$address/readyz" > /dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then cat "$state/start.log" >&2; exit 1; fi
kill -TERM "$pid"
wait "$pid"
pid=""
test -s "$COSMOSIGNER_PKCS11_BINDING_FILE"

# A rejected PIN must keep probes alive without another login, even if the PIN file is corrected.
printf 'wrong-pin\n' > "$state/wrong-pin"
chmod 600 "$state/wrong-pin"
"$binary" start "${common[@]}" --pkcs11-pin-file "$state/wrong-pin" \
  --raft-data-dir "$state/pin-hold-raft" --http-addr 127.0.0.1:0 > "$state/pin-hold.log" 2>&1 &
pid=$!
held=false
for _ in {1..100}; do
  if ! kill -0 "$pid" 2>/dev/null; then cat "$state/pin-hold.log" >&2; exit 1; fi
  address=$(sed -n 's/.*health endpoints listening.*addr=\(127\.0\.0\.1:[0-9]*\).*/\1/p' "$state/pin-hold.log" | head -1)
  if [[ -n "$address" ]] && grep -q 'PKCS#11 startup blocked until restart' "$state/pin-hold.log"; then
    held=true
    break
  fi
  sleep 0.1
done
if [[ "$held" != true ]]; then cat "$state/pin-hold.log" >&2; exit 1; fi
test "$(curl -sS -o /dev/null -w '%{http_code}' "http://$address/livez")" = 200
test "$(curl -sS -o /dev/null -w '%{http_code}' "http://$address/readyz")" = 503
curl -fsS "http://$address/status" | grep -q '"ready":false'
test ! -e "$state/pin-hold-raft"
cp "$COSMOSIGNER_PKCS11_PIN_FILE" "$state/wrong-pin"
sleep 1
kill -0 "$pid"
test "$(curl -sS -o /dev/null -w '%{http_code}' "http://$address/readyz")" = 503
test "$(grep -c 'PKCS#11 startup blocked until restart' "$state/pin-hold.log")" = 1
kill -TERM "$pid"
for _ in {1..100}; do
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if kill -0 "$pid" 2>/dev/null; then echo 'PIN hold did not stop on SIGTERM' >&2; exit 1; fi
wait "$pid"
pid=""
test "$(grep -c 'PKCS#11 startup blocked until restart' "$state/pin-hold.log")" = 1
test "$(grep -c 'err=.*pkcs11 PIN failure latched' "$state/pin-hold.log")" = 1
if curl -fsS --max-time 1 "http://$address/livez" > /dev/null 2>&1; then
  echo 'PIN hold left the health listener open after SIGTERM' >&2
  exit 1
fi
cat "$state/pin-hold.log"

printf 'wrong-pin\n' > "$state/wrong-pin"
"$binary" start "${common[@]}" --pkcs11-pin-file "$state/wrong-pin" \
  --http-addr '' > "$state/pin-exit.log" 2>&1 &
pid=$!
for _ in {1..100}; do
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if kill -0 "$pid" 2>/dev/null; then echo 'PIN failure without HTTP did not exit' >&2; exit 1; fi
if wait "$pid"; then echo 'PIN failure without HTTP exited successfully' >&2; exit 1; fi
pid=""
grep -q 'pkcs11 PIN failure latched' "$state/pin-exit.log"
if grep -q 'PKCS#11 startup blocked until restart' "$state/pin-exit.log"; then
  echo 'PIN failure without HTTP entered the hold' >&2
  exit 1
fi

make build
./bin/cosmosigner version | grep -q 'pkcs11: false'
if ./bin/cosmosigner pubkey > "$state/default.log" 2>&1; then
  echo 'default binary unexpectedly opened a token' >&2
  exit 1
fi
grep -q 'built without PKCS#11 support' "$state/default.log"
printf 'PKCS#11 SoftHSM drill passed: recovery, key replacement, binding, CLI startup and PIN hold/SIGTERM/no-HTTP exit\n'
