#!/usr/bin/env bash
#
# vault-dev.sh — spin up a local HashiCorp Vault (dev mode) configured for
# cosmosigner: the transit engine, a least-privilege policy, and a renewable
# token written to a file for --vault-token-file.
#
# DEV / LOCAL ONLY. Vault dev mode keeps everything in memory, auto-unseals on
# start, and uses a known root token. Never point it at a real validator key.
#
# Usage:
#   scripts/vault-dev.sh up      # start + configure (default)
#   scripts/vault-dev.sh down    # stop + remove the container and token file
#
# Override via env (defaults shown):
#   VAULT_CONTAINER=cosmosigner-vault
#   VAULT_IMAGE=hashicorp/vault:1.15
#   VAULT_PORT=8200
#   VAULT_ROOT_TOKEN=root
#   TRANSIT_MOUNT=transit
#   TOKEN_FILE=./vault-token
set -euo pipefail

VAULT_CONTAINER="${VAULT_CONTAINER:-cosmosigner-vault}"
VAULT_IMAGE="${VAULT_IMAGE:-hashicorp/vault:1.15}"
VAULT_PORT="${VAULT_PORT:-8200}"
VAULT_ROOT_TOKEN="${VAULT_ROOT_TOKEN:-root}"
TRANSIT_MOUNT="${TRANSIT_MOUNT:-transit}"
TOKEN_FILE="${TOKEN_FILE:-./vault-token}"
VAULT_ADDR_HOST="http://127.0.0.1:${VAULT_PORT}"

# Run the vault CLI inside the container, authenticated as root.
vexec() {
	docker exec \
		-e "VAULT_ADDR=http://127.0.0.1:8200" \
		-e "VAULT_TOKEN=${VAULT_ROOT_TOKEN}" \
		"${VAULT_CONTAINER}" vault "$@"
}

up() {
	command -v docker >/dev/null 2>&1 || {
		echo "error: docker not found on PATH" >&2
		exit 1
	}

	echo "==> starting Vault dev container '${VAULT_CONTAINER}' on :${VAULT_PORT}"
	docker rm -f "${VAULT_CONTAINER}" >/dev/null 2>&1 || true
	docker run -d --name "${VAULT_CONTAINER}" \
		--cap-add IPC_LOCK \
		-e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_ROOT_TOKEN}" \
		-e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200" \
		-p "${VAULT_PORT}:8200" \
		"${VAULT_IMAGE}" >/dev/null

	echo -n "==> waiting for Vault"
	for _ in $(seq 1 60); do
		if curl -fsS "${VAULT_ADDR_HOST}/v1/sys/health" >/dev/null 2>&1; then
			echo " ready"
			break
		fi
		echo -n "."
		sleep 0.5
	done
	curl -fsS "${VAULT_ADDR_HOST}/v1/sys/health" >/dev/null 2>&1 || {
		echo " timed out" >&2
		exit 1
	}

	echo "==> enabling transit engine at '${TRANSIT_MOUNT}/'"
	vexec secrets enable -path="${TRANSIT_MOUNT}" transit >/dev/null 2>&1 || echo "    (already enabled)"

	echo "==> writing 'cosmosigner' policy"
	docker exec -i \
		-e "VAULT_ADDR=http://127.0.0.1:8200" \
		-e "VAULT_TOKEN=${VAULT_ROOT_TOKEN}" \
		"${VAULT_CONTAINER}" vault policy write cosmosigner - >/dev/null <<POLICY
# provision / import a consensus key (admin-ish; split out for production)
path "${TRANSIT_MOUNT}/keys/*"       { capabilities = ["create", "read", "update"] }
path "${TRANSIT_MOUNT}/wrapping_key" { capabilities = ["read"] }
# sign — the only capability the running signer strictly needs
path "${TRANSIT_MOUNT}/sign/*"       { capabilities = ["update"] }
POLICY

	echo "==> issuing renewable token"
	local token
	token="$(vexec token create -policy=cosmosigner -period=72h -field=token)"
	(umask 077; printf '%s' "${token}" >"${TOKEN_FILE}")
	echo "    wrote ${TOKEN_FILE} (mode 600)"

	cat <<EOF

Vault is ready for cosmosigner (DEV — in-memory, do not use for real keys).

  VAULT_ADDR     ${VAULT_ADDR_HOST}
  transit mount  ${TRANSIT_MOUNT}/
  token file     ${TOKEN_FILE}

Next steps:

  # generate a NEW consensus key inside Vault
  cosmosigner provision --backend vault \\
    --vault-addr ${VAULT_ADDR_HOST} --vault-token-file ${TOKEN_FILE} --vault-key my-validator

  # OR import an existing validator key (BYOK)
  cosmosigner import --backend vault --from priv_validator_key.json \\
    --vault-addr ${VAULT_ADDR_HOST} --vault-token-file ${TOKEN_FILE} --vault-key my-validator

  # run the signer
  cosmosigner start --chain-id my-chain --node 127.0.0.1:5555 --backend vault \\
    --vault-addr ${VAULT_ADDR_HOST} --vault-token-file ${TOKEN_FILE} --vault-key my-validator \\
    --raft-bootstrap --raft-node-id n0 --raft-bind 127.0.0.1:7070

Tear down: scripts/vault-dev.sh down
EOF
}

down() {
	echo "==> removing Vault container '${VAULT_CONTAINER}'"
	docker rm -f "${VAULT_CONTAINER}" >/dev/null 2>&1 || true
	if [ -f "${TOKEN_FILE}" ]; then
		rm -f "${TOKEN_FILE}"
		echo "    removed ${TOKEN_FILE}"
	fi
	echo "done"
}

case "${1:-up}" in
up) up ;;
down) down ;;
*)
	echo "usage: $0 [up|down]" >&2
	exit 1
	;;
esac
