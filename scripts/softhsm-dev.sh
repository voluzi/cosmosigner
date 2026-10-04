#!/usr/bin/env bash
set -euo pipefail

# Disposable native token only. stdout contains shell exports for eval.
case "${1:-}" in
  up)
    module="${COSMOSIGNER_SOFTHSM_MODULE:-/usr/lib/softhsm/libsofthsm2.so}"
    state=$(mktemp -d "${TMPDIR:-/tmp}/cosmosigner-softhsm.XXXXXX")
    trap 'if [[ $? != 0 ]]; then rm -rf "$state"; fi' EXIT
    mkdir "$state/tokens"
    touch "$state/.cosmosigner-softhsm"
    printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$state" > "$state/softhsm2.conf"
    export SOFTHSM2_CONF="$state/softhsm2.conf"
    printf '123456\n' > "$state/pin"
    chmod 600 "$state/pin"
    softhsm2-util --init-token --free --label cosmosigner-test --so-pin 12345678 --pin 123456 >&2
    pkcs11-tool --module "$module" --list-mechanisms | tee "$state/mechanisms" >&2
    if ! grep -q 'EDDSA' "$state/mechanisms"; then
      echo 'SoftHSM does not expose CKM_EDDSA' >&2
      exit 1
    fi
    pkcs11-tool --module "$module" --token-label cosmosigner-test --login --pin 123456 \
      --keypairgen --key-type EC:edwards25519 --label validator --id 01 >&2
    printf 'export SOFTHSM2_CONF=%q\n' "$SOFTHSM2_CONF"
    printf 'export COSMOSIGNER_PKCS11_MODULE=%q\n' "$module"
    printf 'export COSMOSIGNER_PKCS11_TOKEN_LABEL=cosmosigner-test\n'
    printf 'export COSMOSIGNER_PKCS11_KEY_LABEL=validator\n'
    printf 'export COSMOSIGNER_PKCS11_PIN_FILE=%q\n' "$state/pin"
    printf 'export COSMOSIGNER_PKCS11_BINDING_FILE=%q\n' "$state/binding.json"
    ;;
  down)
    conf="${SOFTHSM2_CONF:-}"
    state="${conf%/*}"
    if [[ -z "${SOFTHSM2_CONF:-}" || ! -f "$state/.cosmosigner-softhsm" ]]; then
      echo 'down requires SOFTHSM2_CONF from this script' >&2
      exit 1
    fi
    rm -rf "$state"
    ;;
  *) echo 'usage: exports=$(scripts/softhsm-dev.sh up) && eval "$exports"; scripts/softhsm-dev.sh down' >&2; exit 1 ;;
esac
