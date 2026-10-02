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
"$binary" start "${common[@]}" --claim-if-unclaimed --http-addr 127.0.0.1:18047 > "$state/start.log" 2>&1 &
pid=$!
ready=false
for _ in {1..100}; do
  if ! kill -0 "$pid" 2>/dev/null; then cat "$state/start.log" >&2; exit 1; fi
  if curl -fsS http://127.0.0.1:18047/readyz > /dev/null 2>&1; then
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

make build
./bin/cosmosigner version | grep -q 'pkcs11: false'
if ./bin/cosmosigner pubkey > "$state/default.log" 2>&1; then
  echo 'default binary unexpectedly opened a token' >&2
  exit 1
fi
grep -q 'built without PKCS#11 support' "$state/default.log"
printf 'PKCS#11 SoftHSM drill passed: recovery, key replacement, binding and CLI startup\n'
