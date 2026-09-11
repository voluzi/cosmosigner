# cosmosigner

[![Test](https://github.com/voluzi/cosmosigner/actions/workflows/test.yml/badge.svg)](https://github.com/voluzi/cosmosigner/actions/workflows/test.yml)
[![Build](https://github.com/voluzi/cosmosigner/actions/workflows/docker-latest.yml/badge.svg)](https://github.com/voluzi/cosmosigner/actions/workflows/docker-latest.yml)
[![GoReleaser](https://github.com/voluzi/cosmosigner/actions/workflows/goreleaser.yml/badge.svg)](https://github.com/voluzi/cosmosigner/actions/workflows/goreleaser.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/voluzi/cosmosigner.svg)](https://pkg.go.dev/github.com/voluzi/cosmosigner)
[![License](https://img.shields.io/github/license/voluzi/cosmosigner)](LICENSE)

A Go-native CometBFT remote signer with **Vault-backed key custody** and
**embedded-raft double-sign protection**. A modern replacement for tmkms that
also borrows horcrux's high-availability model.

## Project status

Cosmosigner is early-stage validator infrastructure. Review the security model,
run it in non-production first, and make sure your deployment has operational
rollback and incident-response procedures before using it with real validator
keys.

## Install

Install the latest release with the Voluzi installer:

```sh
curl -s https://get.voluzi.com/cosmosigner! | bash
```

You can also download binaries from GitHub Releases, use the published container
image, or build from source:

```sh
go install github.com/voluzi/cosmosigner/cmd/cosmosigner@latest
```

Container images are published to GitHub Container Registry:

```sh
docker pull ghcr.io/voluzi/cosmosigner:latest
```

## Why

- **Key custody in Vault or Cloud KMS.** The validator consensus key lives in
  the Vault Transit engine or Google Cloud KMS (`EC_SIGN_ED25519`, PureEdDSA) and
  never leaves it — only signatures cross the wire. A `software` backend is
  provided for local testing.
- **Partition-safe double-sign protection within one signing history.** Every signature must pass through a
  raft-committed high-water-mark (height/round/step). A signer that loses raft
  quorum (e.g. a network partition) **cannot** advance the mark and therefore
  cannot sign — it fails closed (downtime) instead of risking a double-sign.
  This is the lesson lease-based leader election gets wrong. A persistent key-resource claim also
  prevents a newly bootstrapped, independent Raft history from starting with an already-claimed key.
- **Point at any/many nodes, with auto-discovery.** Like horcrux, cosmosigner
  dials a set of node privval endpoints that share one consensus identity —
  either a static list (`--node`) or a Kubernetes headless service it resolves
  and reconciles live (`--node-service`). Nodes are interchangeable sentries/full
  nodes you add or remove freely; the raft mark guarantees exactly one signature
  per height no matter which node asks. Redundancy on both sides: signer replicas
  (raft) × validator nodes.

## Architecture

Two orthogonal, pluggable interfaces:

- **`KeyBackend`** — *who signs.* `software`, `vault`, and `gcpkms` today; AWS
  KMS / HSM later. It remains a signing oracle with no ordering logic, but also exposes the durable
  cluster claim attached to that particular key resource.
- **`StateStore`** — *who decides a height may be signed.* Embedded
  hashicorp/raft today. Consensus ordering stays backend-independent; the startup
  claim prevents a different Raft history from accidentally selecting the same key resource.

Only the raft **leader** holds the node connections and serves signatures. Each
signature follows a strict **reserve → sign → commit** order: the mark is
raft-committed *before* the key backend produces a signature.

An in-flight reservation can be retried by overlapping requests before its signature is committed.
For the same consensus key and sign bytes, every `KeyBackend.Sign` call must therefore return the same
raw Ed25519 signature, including calls through separate backend instances. Duplicate commits reject
non-identical signatures; a backend that cannot provide deterministic signatures needs a different
reservation design.

Before any startup signing probe or node connection, Cosmosigner initializes or loads an immutable
UUID from the Raft log and requires the selected key resource to carry that exact UUID. This is a
startup guardrail, not live fencing: it cannot stop an already-running old binary, detect a complete
copy of the accepted Raft history, or detect the same key material copied into a different resource.

The node dials nothing — it `priv_validator_laddr`-listens, and cosmosigner
dials it over CometBFT's encrypted SecretConnection (CometBFT v0.37.x).

## Quick start (local, software backend)

```sh
make build

# generate a consensus key
./bin/cosmosigner provision --backend software --key-file ./data/priv_validator_key.json

# initialize the Raft history without signing, then claim this key resource
CLUSTER_ID=$(./bin/cosmosigner start \
  --chain-id my-chain --node 127.0.0.1:5555 \
  --backend software --key-file ./data/priv_validator_key.json \
  --raft-bootstrap --raft-single-node --raft-node-id node-1 --raft-bind 127.0.0.1:7070 \
  --raft-insecure --initialize-only)
./bin/cosmosigner claim-key --cluster-id "$CLUSTER_ID" \
  --backend software --key-file ./data/priv_validator_key.json

# run a single-node signer against a local node that has
# priv_validator_laddr = "tcp://0.0.0.0:5555"
./bin/cosmosigner start \
  --chain-id my-chain \
  --node 127.0.0.1:5555 \
  --backend software \
  --key-file ./data/priv_validator_key.json \
  --raft-bootstrap --raft-single-node --raft-node-id node-1 --raft-bind 127.0.0.1:7070 \
  --raft-insecure
```

## Vault backend

```sh
# One-time administrative setup for the immutable binding registry. Keep automatic version
# expiry disabled: deleting the only claim version would remove the startup guardrail.
vault secrets enable -path=cosmosigner -version=2 kv
vault write cosmosigner/config delete_version_after=0s

# create a non-exportable ed25519 transit key
./bin/cosmosigner provision --backend vault \
  --vault-addr https://vault:8200 --vault-token-file /vault/token \
  --vault-key my-validator

# OR migrate an existing validator key (BYOK, imported non-exportable)
./bin/cosmosigner import --backend vault --from priv_validator_key.json \
  --vault-addr https://vault:8200 --vault-token-file /vault/token \
  --vault-key my-validator --vault-key-version 1

# resolve the exact pinned key identity used below
./bin/cosmosigner pubkey --backend vault \
  --vault-addr https://vault:8200 --vault-token-file /vault/token \
  --vault-key my-validator --vault-key-version 1

# With the full signer cluster stopped, run start --initialize-only on the Raft history, then use an
# administrative token to create the immutable KV v2 claim. For one replica:
CLUSTER_ID=$(./bin/cosmosigner start \
  --chain-id my-chain --node 127.0.0.1:5555 \
  --backend vault --vault-addr https://vault:8200 --vault-token-file /vault/runtime-token \
  --vault-mount transit --vault-binding-mount cosmosigner \
  --vault-key my-validator --vault-key-version 1 \
  --raft-bootstrap --raft-single-node --raft-node-id node-1 --raft-bind 127.0.0.1:7070 \
  --raft-insecure --initialize-only)
./bin/cosmosigner claim-key --cluster-id "$CLUSTER_ID" \
  --backend vault --vault-addr https://vault:8200 --vault-token-file /vault/admin-token \
  --vault-mount transit --vault-binding-mount cosmosigner \
  --vault-key my-validator --vault-key-version 1

./bin/cosmosigner start \
  --chain-id my-chain --node 127.0.0.1:5555 \
  --backend vault \
  --vault-addr https://vault:8200 --vault-token-file /vault/token \
  --vault-binding-mount cosmosigner \
  --vault-key my-validator --vault-key-version 1 \
  --expected-public-key '<base64 pubkey from cosmosigner pubkey>' \
  --raft-bootstrap --raft-single-node --raft-node-id node-1 --raft-bind 127.0.0.1:7070 \
  --raft-insecure
```

Vault import is retry-safe: if the selected key version already contains the same public key,
Cosmosigner reports success without calling the create-only import endpoint. It refuses an existing
different identity; use a new Transit key name instead of attempting an in-place overwrite.

Cosmosigner renews renewable and periodic Vault tokens itself, scheduling each
renewal at half the current TTL. A separate token-renewer sidecar is not needed.
Tokens with a finite TTL that cannot be renewed are rejected by the startup
preflight.

The binding registry must be a KV v2 mount (default `cosmosigner`) with automatic expiry disabled.
Do not reuse a generic secret mount whose lifecycle policy can expire or prune this record. The
running signer needs read-only claim access; do not grant it KV writes or Transit administration:

```hcl
# Runtime signer policy.
path "transit/keys/my-validator" { capabilities = ["read"] }
path "transit/sign/my-validator" { capabilities = ["update"] }
path "cosmosigner/data/cluster-bindings/*" { capabilities = ["read"] }
path "cosmosigner/metadata/cluster-bindings/*" { capabilities = ["read"] }
```

Use a separate administrative identity for the one-shot create-only claim. It needs the runtime
reads plus `create` and `update` on the data path because Vault enforces CAS-zero during creation:

```hcl
# One-shot claim administrator policy; do not attach this to the running signer.
path "transit/keys/my-validator" { capabilities = ["read"] }
path "cosmosigner/data/cluster-bindings/*" { capabilities = ["create", "update", "read"] }
path "cosmosigner/metadata/cluster-bindings/*" { capabilities = ["read"] }
```

Do not set a nonzero `delete_version_after`, configure record expiry, or automate deletion of
binding versions/metadata after setup. The explicit `delete_version_after=0s` above keeps
time-based expiry disabled.

Changing `vault-binding-mount` selects a different registry and therefore a different trust domain.

Pin `vault-key-version` for production validators. Version `0` selects Vault's
latest version once at startup and pins signing to that version for the life of
the process, but an explicit version also preserves the intended identity
across restarts after a Transit key rotation. Set `expected-public-key` to the
canonical base64 public key printed by `cosmosigner pubkey`; startup then fails
before opening Raft state if the configured backend resolves to another key.

## Google Cloud KMS backend

Uses an `EC_SIGN_ED25519` key (GA, PureEdDSA — signs the raw consensus bytes).
The key never leaves KMS. Auth uses Application Default Credentials (GKE workload
identity, or `GOOGLE_APPLICATION_CREDENTIALS`); `--gcp-credentials-file` is an
optional override.

The runtime identity needs `roles/cloudkms.signerVerifier` plus
`cloudkms.cryptoKeys.get` on the parent key. `start` runs a preflight that signs a non-consensus probe and verifies it
against the key's public key, so a policy granting only `viewer` — or a key
version that is not `ENABLED` — fails fast at boot instead of at the first vote.

```sh
# create a signing key
./bin/cosmosigner provision --backend gcpkms \
  --gcp-project my-project --gcp-keyring validators --gcp-key my-validator
# prints: key version: projects/.../cryptoKeyVersions/1

# OR migrate an existing validator key (BYOK via a KMS ImportJob)
./bin/cosmosigner import --backend gcpkms --from priv_validator_key.json \
  --gcp-project my-project --gcp-keyring validators --gcp-key my-validator

# confirm connectivity + the consensus address
./bin/cosmosigner pubkey --backend gcpkms \
  --gcp-key-version projects/my-project/locations/global/keyRings/validators/cryptoKeys/my-validator/cryptoKeyVersions/1

# Initialize Raft while every signer is stopped, then serialize this administrative claim so only
# one command can run. The claim identity needs cloudkms.cryptoKeys.get,
# cloudkms.cryptoKeys.update, and cloudkms.cryptoKeyVersions.viewPublicKey.
CLUSTER_ID=$(./bin/cosmosigner start \
  --chain-id my-chain --node 127.0.0.1:5555 \
  --backend gcpkms --gcp-key-version projects/.../cryptoKeyVersions/1 \
  --raft-bootstrap --raft-single-node --raft-node-id node-1 --raft-bind 127.0.0.1:7070 \
  --raft-insecure --initialize-only)
./bin/cosmosigner claim-key --cluster-id "$CLUSTER_ID" \
  --backend gcpkms --gcp-key-version projects/.../cryptoKeyVersions/1 \
  --gcp-credentials-file /secure/admin-credentials.json

# run the signer
./bin/cosmosigner start \
  --chain-id my-chain --node 127.0.0.1:5555 \
  --backend gcpkms \
  --gcp-key-version projects/.../cryptoKeyVersions/1 \
  --raft-bootstrap --raft-single-node --raft-node-id node-1 --raft-bind 127.0.0.1:7070 \
  --raft-insecure
```

Cloud KMS has no conditional update field for CryptoKey labels. Initial GCP claiming is therefore
not atomic: stop all signers and externally serialize the claim command. Cosmosigner preserves
unrelated labels, changes only `cosmosigner-cluster-id`, and reads it back, but concurrent initial
claim commands can both appear successful. Normal `start` is read-only for labels and never claims.

End-to-end sign+verify test against a real key (no node needed):

```sh
GCP_KMS_KEY_VERSION=projects/.../cryptoKeyVersions/1 \
  go test -tags gcpkms_integration -run GCPKMS ./internal/backend/
```

> Migrating an existing validator? Its consensus pubkey is on-chain, so use
> `cosmosigner import` instead of `provision` — it extracts the 32-byte seed
> from `priv_validator_key.json`, converts to PKCS#8 DER, wraps it, and imports
> it non-exportable. `import` prints the consensus address so you can confirm it
> matches the chain. Securely destroy file copies of the key afterwards.

## Target-node discovery (Kubernetes)

Instead of a static `--node` list, point cosmosigner at a headless service and it
discovers the node pods from DNS, reconciling the connection set every few
seconds — pods that appear get a signer, pods that vanish are dropped:

```sh
cosmosigner start --chain-id my-chain \
  --node-service sentries.my-ns.svc.cluster.local:5555 \
  --backend gcpkms --gcp-key-version projects/.../cryptoKeyVersions/1 \
  --raft-bootstrap --raft-single-node --raft-node-id node-1 --raft-bind 0.0.0.0:7070 \
  --raft-tls-cert /tls/raft-cert.pem --raft-tls-key /tls/raft-key.pem \
  --raft-tls-ca /tls/raft-ca.pem
```

> **The headless service MUST set `publishNotReadyAddresses: true`.** A node with
> `priv_validator_laddr` set blocks at startup until a signer dials in. If the
> service only published *ready* pods, a starting node wouldn't be in DNS, so
> cosmosigner wouldn't connect, so the node would never become ready — a
> deadlock. Publishing not-ready addresses lets cosmosigner connect the moment a
> pod exists and unblock it. (Discovery is DNS-only — no Kubernetes API/RBAC.)

Discovery applies only to the *target nodes* (signature consumers, protected by
the raft gate). The raft member set stays **static** on purpose — it's the
signing quorum's trust boundary, not something to auto-join.

Reconciliation is not purely periodic: connection health is also sampled between
ticks, and a connection that dies triggers an immediate re-resolve rather than
waiting out `--reconcile-interval`. This matters because a node pod that dies is
usually replaced at a **new IP**, so the resolved address is stale the moment the
pod goes away — tying recovery to the tick makes an ordinary node restart look
like a multi-minute outage.

Cosmosigner also waits for its own `--raft-advertise` address to become
resolvable at startup (up to 90s) instead of exiting immediately. Under a
StatefulSet the per-pod DNS record is published moments after the pod starts, so
resolving once and exiting turns an ordinary startup race into a crashloop. A
genuinely wrong address still fails, just after the retry budget.

## High availability (raft cluster)

Run an odd number of replicas (3 tolerates 1 failure, 5 tolerates 2). Every node
is given the **identical full member list** (`--raft-member id=address`, including
itself); the addresses are the raft advertise addresses peers use to reach each
other. Exactly **one** node seeds the cluster with `--raft-bootstrap`; the others
start without it and the leader pulls them in. (A node started with
`--raft-bootstrap` validates that its own `--raft-node-id` is in the member list,
which catches the usual split-brain misconfiguration.)

```sh
# Start all three in --initialize-only mode together; quorum is required. Node 0 is the bootstrapper.
cosmosigner start ... --initialize-only --raft-node-id n0 --raft-bind 0.0.0.0:7070 --raft-bootstrap \
  --raft-tls-cert /tls/raft-cert.pem --raft-tls-key /tls/raft-key.pem \
  --raft-tls-ca /tls/raft-ca.pem \
  --raft-member n0=cs-0.cs.ns.svc:7070 \
  --raft-member n1=cs-1.cs.ns.svc:7070 \
  --raft-member n2=cs-2.cs.ns.svc:7070
# nodes 1 and 2: same initialization command but WITHOUT --raft-bootstrap
# All print the same cluster ID and remain alive to preserve quorum. Record that ID, then stop all
# participants together, claim the key once, and restart all without --initialize-only. A lone
# replica cannot initialize a three-voter cluster.
```

In a StatefulSet this is one templated arg set plus a per-ordinal
`COSMOSIGNER_RAFT_BOOTSTRAP=true` on pod 0 only. A single-node development
signer uses `--raft-bootstrap --raft-single-node --raft-insecure` with no
`--raft-member`. Bootstrapping with an empty member list requires the explicit
`--raft-single-node` opt-in (YAML `raft.single_node: true` or
`COSMOSIGNER_RAFT_SINGLE_NODE=true`). It defaults to false. Single-node initialization exits after
printing, so command substitution remains suitable for that mode.
Multi-member `--initialize-only` processes intentionally stay running after printing until they
receive SIGINT or SIGTERM; otherwise early replicas can remove the quorum before slower members
learn the identity. Existing single-node invocations must add this opt-in as part of the same
upgrade, even when their
Raft state already exists. The previous release rejects the new CLI flag and
YAML key, so only the environment variable form can be added ahead of time.
Replicated signers must provide their full initial member list;
never enable single-node bootstrap on independent replicas sharing a signing key.
Target-node discovery and the bind address do not determine the signer topology.

At startup, the Raft log records the node ID, bind and advertise addresses,
configured member list, single-node opt-in, bootstrap request, whether existing
state was found, and whether bootstrap will run. Existing state is reused;
bootstrap only runs on an empty store.

The immutable cluster ID is stored in that same log and in versioned snapshots beside the signing
high-water marks. A fresh data directory receives a different ID and refuses an already-claimed key.
Legacy snapshots retain every mark and receive an ID through the ordered Raft initializer.

### Upgrade and recovery requirement

This format and claim check require a full stopped-cluster upgrade; mixed old/new replicas and
downgrade are unsupported. Stop every old signer and disable restarts, preserve the complete
authoritative Raft directories, revoke old remote credentials where applicable, install the new
binary everywhere, run `start --initialize-only` with the existing directories and a quorum, claim
the key once under administrative credentials, then grant runtime claim-read permission and restart
normally. Verify that a fresh independent data directory refuses the claimed key.

Moving a validator transfers the complete current Raft history and its identity only after the old
deployment is operationally fenced. Never copy only the UUID, use a stale snapshot, clear the
high-water mark, or delete/relabel a claim after losing all authoritative state. Recover the correct
history or use an independently safe validator key-rotation/recovery procedure.

Because raft is **CP**, a node in a minority partition cannot commit the
high-water-mark and therefore cannot sign — it fails closed (downtime) rather
than double-signing. Losing the leader triggers an election among the survivors;
the new leader already holds the replicated high-water-mark, so no height can be
re-signed. (All of this — formation, replication, failover — is covered by
`internal/state/cluster_test.go`.)

### Securing the raft transport

The inter-replica raft transport requires **mutual TLS by default** because it
protects the integrity of the double-sign gate. Point all three of
`--raft-tls-cert` / `--raft-tls-key` / `--raft-tls-ca` (env `COSMOSIGNER_RAFT_TLS_CERT`
/ `_KEY` / `_CA`, or YAML `raft.tls_cert` / `tls_key` / `tls_ca`) at a PEM keypair
and CA bundle. They are **all-or-nothing**; a partial set is rejected at startup.

Local development can explicitly opt out with `--raft-insecure`, YAML
`raft.insecure: true`, or `COSMOSIGNER_RAFT_INSECURE=true`. Insecure mode logs a
warning on every startup and cannot be combined with TLS configuration.

Existing plain-TCP deployments must choose a transport mode before upgrading:
set the explicit insecure opt-out for isolated development, or distribute the
certificates and switch every replica to mTLS in a coordinated maintenance
window. Plain-TCP and mTLS replicas cannot communicate, so expect a leader
election and a brief fail-closed signing pause during the cutover.

When enabled, every replica must present a certificate signed by the configured
CA (`RequireAndVerifyClientCert`) and dialers verify the peer's chain, so a node
without a CA-signed cert cannot join the cluster. Each cert must list the node's
raft **advertise** host (IP or DNS) in its SANs, since dialers verify it. One
keypair can be shared by every replica, or issue one per node from the same CA.
(Covered by `internal/state/tls_test.go`: cluster formation over mTLS and
rejection of an untrusted peer.)

> Note: this secures only cosmosigner's **own** raft mesh. The node↔signer
> (privval) link is already encrypted and mutually authenticated by CometBFT's
> SecretConnection; it cannot be peer-pinned, because a stock CometBFT node
> generates a fresh, ephemeral SecretConnection key on every start (see the
> `NewSignerListener` TODO in cometbft), so there is no stable node identity to
> allow-list. Protect that link with network topology (co-location, a private
> mesh) instead.

## Environment variables

Every config field declares its `COSMOSIGNER_*` env var (and YAML key and
default) as struct tags in `internal/config`; `config.Load` layers them with
precedence **flag > env > config file > default**. List values
(`COSMOSIGNER_NODE`) are comma-separated. (The one-shot key-provisioning
coordinates — `--gcp-project`/`--gcp-keyring`/`--gcp-key` etc. — are flag-only.)

```sh
export COSMOSIGNER_CHAIN_ID=my-chain
export COSMOSIGNER_NODE_SERVICE=sentries.my-ns.svc.cluster.local:5555
export COSMOSIGNER_BACKEND=gcpkms
export COSMOSIGNER_GCP_KEY_VERSION=projects/.../cryptoKeyVersions/1
# Vault deployments can select the KV v2 claim registry:
# export COSMOSIGNER_VAULT_BINDING_MOUNT=cosmosigner
export COSMOSIGNER_RAFT_NODE_ID=node-1
export COSMOSIGNER_RAFT_BIND=0.0.0.0:7070
export COSMOSIGNER_RAFT_BOOTSTRAP=true
export COSMOSIGNER_RAFT_SINGLE_NODE=true
export COSMOSIGNER_RAFT_TLS_CERT=/tls/raft-cert.pem
export COSMOSIGNER_RAFT_TLS_KEY=/tls/raft-key.pem
export COSMOSIGNER_RAFT_TLS_CA=/tls/raft-ca.pem
cosmosigner start   # fully configured from the environment
```

## Config file

All flags can come from a YAML file (`--config cosmosigner.yaml`); explicitly-set
flags override it.

```yaml
chain_id: my-chain
expected_public_key: <canonical base64 consensus public key>
nodes:                       # static list, OR use node_service (mutually exclusive)
  - 10.0.0.1:5555
  - 10.0.0.2:5555
# node_service: sentries.my-ns.svc.cluster.local:5555
conn_key: /data/conn_key.json
backend:
  type: vault
  vault:
    address: https://vault:8200
    token_file: /vault/token
    binding_mount: cosmosigner
    key_name: my-validator
    key_version: 1
raft:
  node_id: node-1
  bind_addr: 0.0.0.0:7070
  data_dir: /data/raft
  bootstrap: true            # on exactly one node
  single_node: false         # set true only to bootstrap with no members
  members:                   # full set incl self, identical on every node
    - { id: node-1, address: 10.0.1.1:7070 }
    - { id: node-2, address: 10.0.1.2:7070 }
    - { id: node-3, address: 10.0.1.3:7070 }
  tls_cert: /tls/raft-cert.pem
  tls_key: /tls/raft-key.pem
  tls_ca: /tls/raft-ca.pem
```

## Development

```sh
make build
make test
make vet
```

`make test-cover` runs the race detector and writes `coverage.out`, matching CI.
The default suite exercises the signature-determinism contract with the software backend.
Provider conformance tests are opt-in and must use dedicated test keys, never validator keys:

```sh
# Real Vault Transit backend; starts a disposable local Vault first.
scripts/vault-dev.sh up
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
  go test -race -tags vault_integration ./internal/backend \
  -run TestVaultIntegration_SignDeterminism -count=1 -v
scripts/vault-dev.sh down

# Real Cloud KMS backend using a designated EC_SIGN_ED25519 test key version.
GCP_KMS_KEY_VERSION=projects/.../cryptoKeyVersions/1 \
  go test -race -tags gcpkms_integration ./internal/backend \
  -run TestGCPKMS_SignVerify -count=1 -v
```

The Cloud KMS result establishes conformance only for the configured key version and its protection
level. Run it for every production-equivalent KMS configuration. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for provider setup details.

## Security and responsible disclosure

Cosmosigner is security-sensitive because it gates validator signatures. If you
find a vulnerability, do not open a public issue; follow
[`SECURITY.md`](SECURITY.md).

For production deployments:

- Prefer a remote custody backend (`vault` or `gcpkms`) over `software`.
- Use private networking and firewall policy between validators, signers, raft
  peers, Vault, and KMS endpoints.
- Keep raft mTLS enabled in production; use `raft.insecure` only for isolated
  local development.
- Keep validator key files, Vault tokens, KMS credentials, raft data, and local
  test data out of source control and unaudited backups.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE).
