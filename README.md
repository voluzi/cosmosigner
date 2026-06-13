# cosmosigner

A Go-native CometBFT remote signer with **Vault-backed key custody** and
**embedded-raft double-sign protection**. A modern replacement for tmkms that
also borrows horcrux's high-availability model.

## Why

- **Key custody in Vault or Cloud KMS.** The validator consensus key lives in
  the Vault Transit engine or Google Cloud KMS (`EC_SIGN_ED25519`, PureEdDSA) and
  never leaves it — only signatures cross the wire. A `software` backend is
  provided for local testing.
- **Partition-safe double-sign protection.** Every signature must pass through a
  raft-committed high-water-mark (height/round/step). A signer that loses raft
  quorum (e.g. a network partition) **cannot** advance the mark and therefore
  cannot sign — it fails closed (downtime) instead of risking a double-sign.
  This is the lesson lease-based leader election gets wrong.
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
  KMS / HSM later. A pure signing oracle: no ordering logic.
- **`StateStore`** — *who decides a height may be signed.* Embedded
  hashicorp/raft today; the gate is decoupled from the key backend so adding a
  key service (which has no consistent-counter primitive) never reopens the
  double-sign question.

Only the raft **leader** holds the node connections and serves signatures. Each
signature follows a strict **reserve → sign → commit** order: the mark is
raft-committed *before* the key backend produces a signature.

The node dials nothing — it `priv_validator_laddr`-listens, and cosmosigner
dials it over CometBFT's encrypted SecretConnection (CometBFT v0.37.x).

## Quick start (local, software backend)

```sh
make build

# generate a consensus key
./bin/cosmosigner provision --backend software --key-file ./data/priv_validator_key.json

# run a single-node signer against a local node that has
# priv_validator_laddr = "tcp://0.0.0.0:5555"
./bin/cosmosigner start \
  --chain-id my-chain \
  --node 127.0.0.1:5555 \
  --backend software \
  --key-file ./data/priv_validator_key.json \
  --raft-bootstrap --raft-node-id node-1 --raft-bind 127.0.0.1:7070
```

## Vault backend

```sh
# create a non-exportable ed25519 transit key
./bin/cosmosigner provision --backend vault \
  --vault-addr https://vault:8200 --vault-token-file /vault/token \
  --vault-key my-validator

# OR migrate an existing validator key (BYOK, imported non-exportable)
./bin/cosmosigner import --backend vault --from priv_validator_key.json \
  --vault-addr https://vault:8200 --vault-token-file /vault/token \
  --vault-key my-validator

./bin/cosmosigner start \
  --chain-id my-chain --node 127.0.0.1:5555 \
  --backend vault \
  --vault-addr https://vault:8200 --vault-token-file /vault/token \
  --vault-key my-validator \
  --raft-bootstrap --raft-node-id node-1 --raft-bind 127.0.0.1:7070
```

## Google Cloud KMS backend

Uses an `EC_SIGN_ED25519` key (GA, PureEdDSA — signs the raw consensus bytes).
The key never leaves KMS. Auth uses Application Default Credentials (GKE workload
identity, or `GOOGLE_APPLICATION_CREDENTIALS`); `--gcp-credentials-file` is an
optional override.

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

# run the signer
./bin/cosmosigner start \
  --chain-id my-chain --node 127.0.0.1:5555 \
  --backend gcpkms \
  --gcp-key-version projects/.../cryptoKeyVersions/1 \
  --raft-bootstrap --raft-node-id node-1 --raft-bind 127.0.0.1:7070
```

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
  --raft-bootstrap --raft-node-id node-1 --raft-bind 0.0.0.0:7070
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

## High availability (raft cluster)

Run an odd number of replicas (3 tolerates 1 failure, 5 tolerates 2). Every node
is given the **identical full member list** (`--raft-member id=address`, including
itself); the addresses are the raft advertise addresses peers use to reach each
other. Exactly **one** node seeds the cluster with `--raft-bootstrap`; the others
start without it and the leader pulls them in. (A node started with
`--raft-bootstrap` validates that its own `--raft-node-id` is in the member list,
which catches the usual split-brain misconfiguration.)

```sh
# node 0 (the one bootstrapper)
cosmosigner start ... --raft-node-id n0 --raft-bind 0.0.0.0:7070 --raft-bootstrap \
  --raft-member n0=cs-0.cs.ns.svc:7070 \
  --raft-member n1=cs-1.cs.ns.svc:7070 \
  --raft-member n2=cs-2.cs.ns.svc:7070
# nodes 1 and 2: same flags but WITHOUT --raft-bootstrap
```

In a StatefulSet this is one templated arg set plus a per-ordinal
`COSMOSIGNER_RAFT_BOOTSTRAP=true` on pod 0 only. A single-node signer just uses
`--raft-bootstrap` with no `--raft-member`.

Because raft is **CP**, a node in a minority partition cannot commit the
high-water-mark and therefore cannot sign — it fails closed (downtime) rather
than double-signing. Losing the leader triggers an election among the survivors;
the new leader already holds the replicated high-water-mark, so no height can be
re-signed. (All of this — formation, replication, failover — is covered by
`internal/state/cluster_test.go`.)

### Securing the raft transport (optional mTLS)

By default the inter-replica raft transport is **plain TCP** — fine when the
replicas talk over a trusted/isolated network (e.g. a pod network with policies).
To authenticate and encrypt the replica-to-replica link, point all three of
`--raft-tls-cert` / `--raft-tls-key` / `--raft-tls-ca` (env `COSMOSIGNER_RAFT_TLS_CERT`
/ `_KEY` / `_CA`, or YAML `raft.tls_cert` / `tls_key` / `tls_ca`) at a PEM keypair
and CA bundle. They are **all-or-nothing**: set all three to enable mutual TLS,
or none to stay on plain TCP (a partial set is rejected at startup).

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
export COSMOSIGNER_RAFT_NODE_ID=node-1
export COSMOSIGNER_RAFT_BIND=0.0.0.0:7070
export COSMOSIGNER_RAFT_BOOTSTRAP=true
cosmosigner start   # fully configured from the environment
```

## Config file

All flags can come from a YAML file (`--config cosmosigner.yaml`); explicitly-set
flags override it.

```yaml
chain_id: my-chain
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
    key_name: my-validator
raft:
  node_id: node-1
  bind_addr: 0.0.0.0:7070
  data_dir: /data/raft
  bootstrap: true            # on exactly one node
  members:                   # full set incl self, identical on every node
    - { id: node-1, address: 10.0.1.1:7070 }
    - { id: node-2, address: 10.0.1.2:7070 }
    - { id: node-3, address: 10.0.1.3:7070 }
  # optional mutual TLS on the raft mesh (all three or none)
  # tls_cert: /tls/raft-cert.pem
  # tls_key: /tls/raft-key.pem
  # tls_ca: /tls/raft-ca.pem
```

## Status

v1: software + Vault Transit + Google Cloud KMS backends (provision + BYOK
import), embedded-raft state store, env-var config, single chain.
Not yet: AWS KMS backend, external CP state stores.
