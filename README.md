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

- **Key custody in Vault, Google Cloud KMS or AWS KMS.** The validator consensus key lives in
  the Vault Transit engine, Google Cloud KMS (`EC_SIGN_ED25519`) or AWS KMS
  (`ECC_NIST_EDWARDS25519`), using PureEdDSA, and
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

- **`KeyBackend`** — *who signs.* `software`, `vault`, `gcpkms`, and `awskms`. It remains a signing oracle with no ordering logic, but also exposes the durable
  cluster claim attached to that particular key resource.
- **`StateStore`** — *who decides a height may be signed.* Embedded
  hashicorp/raft today. Consensus ordering stays backend-independent; the startup
  claim prevents a different Raft history from accidentally selecting the same key resource.

Each validator identity uses an independent Cosmosigner/Raft deployment, which may contain
multiple signer replicas. A deployment configures one chain and one `KeyBackend`; all target node
connections share that validator key and signing history. Do not multiplex chains or validator
keys through one process. The chain-keyed FSM storage is headroom, not a supported multi-chain or
multi-key mode. Separate deployments isolate key configuration, signing history, and failure
domains.

`StateStore.Get` returns a snapshot of the local FSM without a leadership, quorum, or read-index
check, so it may be stale. It is for diagnostics only and must not be used to authorize signing; a
future linearizable read requires a separate API.

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
dials it over CometBFT's encrypted SecretConnection. This release is built and
tested against exactly CometBFT v0.38.26; CometBFT v1.x is not supported.

For a non-nil precommit, Cosmosigner signs both the canonical vote and the vote
extension. Only the canonical vote bytes pass through the Raft double-sign gate
and are persisted. The non-deterministic extension is signed separately on every
request, including an empty extension and same-height/round/step replay, so each
accepted non-nil precommit makes one additional `KeyBackend.Sign` call. Prevotes
and nil precommits reject non-empty extensions and return no extension signature.

CometBFT v0.38.26's upstream `privval/signer_endpoint.go` limits each serialized
remote-signer protobuf message, excluding its outer length prefix, to 10 KiB.
The vote extension shares that limit with the rest of the sign-vote request or
response and its protobuf envelope; 10 KiB is not available to the extension
payload alone.

The `awskms` backend has a stricter limit: the complete extension sign-bytes
(including their canonical encoding) must fit within AWS KMS's 4096-byte RAW
message limit. Do not use this backend on chains that require larger extensions;
such a precommit fails to sign even when its remote-signer envelope fits within 10 KiB.

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

# Token self-management. Vault's built-in `default` policy already grants these. A token created
# with `-no-default-policy` (as tmKMS setups do) needs them in its own policy, alongside everything
# above.
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "sys/capabilities-self" { capabilities = ["update"] }  # optional
```

`lookup-self` is required: without it Cosmosigner cannot see the token's TTL, so it could never renew
it, and the startup preflight rejects the token. `renew-self` is needed for renewable and periodic
tokens. `sys/capabilities-self` is optional: when it is denied, the preflight skips the capability
check and relies on its sign probe against `transit/sign/<key>`. A tmKMS token reused as-is also
lacks the `cluster-bindings` reads above, so extend its policy before migrating.

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

## AWS KMS backend

Uses a customer-managed, single-Region `ECC_NIST_EDWARDS25519` / `SIGN_VERIFY` key.
Only `ED25519_SHA_512` with `MessageType: RAW` is used; the prehashed
`ED25519_PH_SHA_512` variant is incompatible with CometBFT. Raw messages must be
1–4096 bytes. Construction checks the advertised algorithm and DER SPKI public key.
This limit also applies to canonical vote-extension sign-bytes, so this backend is
unsuitable for chains whose extensions can exceed it.
Every sign response must identify the pinned key ARN, advertise the requested algorithm,
contain 64 bytes, and verify locally against the cached public key.

Key IDs, key ARNs, aliases and alias ARNs are accepted for signing. An alias is resolved
once at startup; subsequent requests use only the returned key ARN, and response ARNs
must match it. Prefer a key ARN in production. `start` signs a non-consensus probe twice,
verifies each response, and rejects different signatures. This is an empirical startup
check, not a provider guarantee of determinism; run the conformance drill with a dedicated
production-equivalent test key before deployment.

Credentials use the standard AWS SDK chain: environment variables, shared profiles,
web identity/IRSA, ECS task roles, and EC2 instance profiles. Region resolution uses
`--aws-region` / `COSMOSIGNER_AWS_REGION` / `backend.aws.region` when specified,
otherwise the SDK region chain (`AWS_REGION`, `AWS_DEFAULT_REGION`, shared config).
For `start --claim-if-unclaimed`, `--aws-claim-role-arn` / `backend.aws.claim_role_arn` /
`COSMOSIGNER_AWS_CLAIM_ROLE_ARN` optionally selects a role assumed through the SDK's
standard STS credentials provider for the claim only. The runtime identity needs
`sts:AssumeRole` on that role, and the role's trust policy must allow that runtime
principal. The role also needs the same key permissions as `claim-key`.
Without a claim role, startup claiming uses the runtime identity and requires
`kms:TagResource`. An unused claim role ARN is simply unused. Standalone `claim-key`
always uses the caller's standard credential chain, like `import` and `pubkey`.

| Operation | AWS permissions |
|---|---|
| Runtime / `start` | `kms:GetPublicKey`, `kms:Sign`, `kms:ListResourceTags` on the key |
| `pubkey` | `kms:GetPublicKey` on the key |
| `claim-key` | `kms:GetPublicKey`, `kms:ListResourceTags`, `kms:TagResource` on the key |
| `provision` | `kms:CreateKey` (a new resource; IAM resource `*`) |
| `import` into an existing target | `kms:DescribeKey`, `kms:ListResourceTags`, `kms:GetParametersForImport`, `kms:ImportKeyMaterial`, `kms:GetPublicKey` on the key |
| `import` into a new target | `kms:CreateKey` (IAM resource `*`), plus the existing-target permissions above on the created key; alias targets also require `kms:DescribeKey` for alias lookup and `kms:CreateAlias` on the alias (IAM policy) and on the new key (key policy) |
| Import integration drill cleanup | `kms:ScheduleKeyDeletion` on the created test key |

Key-level operations must also be allowed by the key policy; grant `kms:CreateKey`
through the caller's IAM policy. New keys use the default
AWS key policy; custom policies and tags are administered outside this command.
Import can create a missing alias but never replaces one. See the
[CreateAlias permissions](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html)
and [key-state table](https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html)
(`CreateAlias` is allowed in `PendingImport`).
Use the same AWS account and Region for the signer and key. Cross-account cluster
binding is unsupported because tag operations do not support cross-account access.
Multi-Region keys (`mrk-`) are rejected: replicas share material but their tags are
independent and unsynchronized, so regional claims cannot protect one history. See
[AWS Multi-Region key behavior](https://docs.aws.amazon.com/kms/latest/developerguide/mrk-how-it-works.html).

The `cosmosigner-cluster-id` key tag binds the key to one Raft signing history.
**AWS KMS tag writes have no compare-and-set, and tag reads are eventually consistent.**
Stop every signer, externally serialize the initial claim, and allow any prior claim
to become visible before claiming. A stale read can miss another owner's claim;
read-back polling cannot make concurrent claims safe. Cosmosigner never rewrites a
visible existing claim and refuses mismatched, corrupt, or unreadable claims. Initial
claims perform at most eight read-back attempts, spaced 250 ms apart, under the configured
timeout. If propagation takes longer, retry with the same cluster ID. Restrict tag mutation
and removal permissions; an administrator who rewrites or removes this tag can break
history protection. See [AWS KMS eventual consistency](https://docs.aws.amazon.com/kms/latest/developerguide/programming-eventual-consistency.html).

The command substitution below is for a single-member Raft configuration with
`http_addr` unset. For multiple members, follow the [Raft cluster](#high-availability-raft-cluster)
initialize/capture/stop sequence: initialization participants stay alive to keep quorum.

```sh
# Create a new signing key; record the printed ARN.
./bin/cosmosigner provision --backend awskms --aws-region eu-west-1

# Import an existing validator identity using a stable alias target.
./bin/cosmosigner import --backend awskms --aws-region eu-west-1 \
  --aws-key-id alias/my-validator --from priv_validator_key.json

# Set KEY_ARN to the ARN printed after "imported key version:" (or by provision).
./bin/cosmosigner pubkey --backend awskms --aws-region eu-west-1 --aws-key-id "$KEY_ARN"
CLUSTER_ID=$(./bin/cosmosigner start --config cosmosigner.yaml --initialize-only)
./bin/cosmosigner claim-key --backend awskms --aws-region eu-west-1 \
  --aws-key-id "$KEY_ARN" --cluster-id "$CLUSTER_ID"
./bin/cosmosigner start --config cosmosigner.yaml
```

The corresponding backend configuration is:

```yaml
backend:
  type: awskms
  aws:
    key_id: arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012
    region: eu-west-1
```

`COSMOSIGNER_AWS_KEY_ID` selects the key; `COSMOSIGNER_AWS_TIMEOUT` bounds operations
(default `10s`, environment only). `provision` always creates a new key and refuses
`--aws-key-id`. CreateKey retries are disabled because it has no idempotency token:
a lost response can leave a created key, so inspect KMS before retrying.

`import --aws-key-id alias/<name>` resolves the alias or, when it is missing,
creates a customer-managed, single-Region EXTERNAL Ed25519 key and publishes the alias
before importing material. An existing alias, key ID or key ARN follows the same path:
`PendingImport` resumes the import; `Enabled` returns success without writes only when
its public key matches the source. A different identity fails without writes. A missing
key ID, key ARN or alias ARN is an error and never creates a replacement. Automatic
creation accepts alias names only; an alias ARN retains its explicit account and Region
and must already exist. Omitting
`--aws-key-id` creates a new key on every run; use an alias for retried imports.
The command checks any existing cluster claim and preserves it. A valid claim can
accompany recovery after imported material was deleted: AWS permits only the original immutable material to be
restored. The import uses DER PKCS#8, a `RSA_4096` wrapping key, OAEP SHA-256, and
`KEY_MATERIAL_DOES_NOT_EXPIRE`. All responses are checked against the pinned ARN; the
imported public key must match the source before the command reports verified success.
If AWS accepted the material but its public key cannot yet be read (including permission
failures or an expired timeout), the command prints the expected identity and the
`pubkey` command for a later check. Fix the read permissions or wait for availability;
verify identity before signing. ARN, algorithm or public-key mismatches remain hard
errors. Once a PendingImport target is resolved, errors retain its ARN: failures before
acceptance advise inspecting the key state before resuming with `--aws-key-id`, while
failures after acceptance advise verifying identity with `pubkey`.

Import prints `imported key version: <key ARN>` for verified, deferred and matching
Enabled targets. `pubkey` prints `aws key arn:    <key ARN>` before the consensus identity.
Configure the signer with that immutable ARN: an alias is a lookup name, and anyone with
`kms:UpdateAlias` can retarget it.

`CreateKey` and `CreateAlias` are separate, non-transactional calls. A crash or lost
response between them can leave an unaliased EXTERNAL key in `PendingImport`. An immediate
retry can also see a stale alias lookup, create another key, then fail to publish the
alias. Two concurrent first runs can each create a key; one alias creation fails.
Errors report the candidate key ARN when available, including alias creation failures.
If the process died before reporting it, find the key in KMS. Inspect its state, then
resume with `--aws-key-id <ARN>`, point the alias at it, or schedule its deletion as
appropriate. Cosmosigner does not scan tags for recovery, replace aliases or delete keys
automatically.

**Retain a protected recovery backup of the original imported material outside AWS,
preferably in an HSM.** AWS customers are responsible for its durability; imported
material can be deleted or become unavailable and cannot be exported from KMS.
Follow [AWS protection of imported material](https://docs.aws.amazon.com/kms/latest/developerguide/import-keys-protect.html)
and [imported-key considerations](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-considerations.html).
Retire unsecured working copies only after confirming the identity and protecting the
recovery backup. AWS imports must never follow a destroy-all-copies procedure.

Provider conformance and import drills are opt-in. Real-AWS validation of alias creation,
PendingImport resume, Enabled reruns and the startup STS claim role remains pending;
local HTTP tests do not establish those provider behaviors:

```sh
AWS_REGION=eu-west-1 AWS_KMS_KEY_ID='<dedicated-test-key-arn>' \
  go test -race -tags awskms_integration -run TestAWSKMSIntegrationSignDeterminism ./internal/backend/

# Creates a billable EXTERNAL test key; schedules deletion with the 7-day minimum window.
AWS_REGION=eu-west-1 AWS_KMS_IMPORT_TEST=1 \
  go test -race -tags awskms_integration -run TestAWSKMSIntegrationImportRoundTrip ./internal/backend/
```

## Google Cloud KMS backend

Uses an `EC_SIGN_ED25519` key (GA, PureEdDSA — signs the raw consensus bytes).
The key never leaves KMS. Auth uses Application Default Credentials (GKE workload
identity, or `GOOGLE_APPLICATION_CREDENTIALS`); `--gcp-credentials-file` is an
optional override.

The runtime identity needs `roles/cloudkms.signerVerifier` plus
`cloudkms.cryptoKeys.get` on the parent key. `start` runs a preflight that signs a non-consensus probe and verifies it
against the key's public key, so a policy granting only `viewer` — or a key
version that is not `ENABLED` — fails fast at boot instead of at the first vote.

`import` reads existing resources before creating anything, so importing into an existing
CryptoKey needs only:

| Permission | Granted on |
|---|---|
| `cloudkms.cryptoKeys.get` | the CryptoKey |
| `cloudkms.cryptoKeyVersions.create`, `cloudkms.cryptoKeyVersions.get`, `cloudkms.cryptoKeyVersions.viewPublicKey` | the CryptoKey |
| `cloudkms.importJobs.get`, `cloudkms.importJobs.useToImport` | the key ring, or the ImportJob when it (default `<key>-import`) already exists |
| `cloudkms.importJobs.create` | the key ring — unless `--gcp-import-job` names an existing job that is `ACTIVE` or still `PENDING_GENERATION` |

`viewPublicKey` lets `import` verify the imported identity. An existing CryptoKey must be
`ASYMMETRIC_SIGN` with an `EC_SIGN_ED25519` version template at the requested `--gcp-protection`
level (an import-only key is fine), and an existing ImportJob must use `RSA_OAEP_3072_SHA256` or
`RSA_OAEP_4096_SHA256` at that level; `import` fails otherwise.

Cloud KMS checks permissions before existence, so a read of a resource that does not exist yet
returns `PermissionDenied`, not `NotFound`, unless it is granted on a parent that does exist. When
the CryptoKey is missing, `import` creates it, which additionally needs `cloudkms.keyRings.get` and
`cloudkms.cryptoKeys.create`, with every CryptoKey permission above granted on the key ring. When the
key ring is missing too, `import` also creates it with `cloudkms.keyRings.create`; there is nothing
to bind to below the project yet, so that and every permission above must be granted on the project.

`provision` also reads the key ring first and creates it only on `NotFound`; any other read
error stops provisioning. It always fails if the CryptoKey already exists. Creating the key
includes its initial version and needs these permissions:

| Target | Permissions | Granted on |
|---|---|---|
| Existing key ring | `cloudkms.keyRings.get`, `cloudkms.cryptoKeys.create` | the key ring |
| New key ring | `cloudkms.keyRings.get`, `cloudkms.keyRings.create`, `cloudkms.cryptoKeys.create` | the project |

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
claim commands can both appear successful. Normal `start` is read-only for labels and never claims
unless `--claim-if-unclaimed` is set (see [Claiming at startup](#claiming-at-startup)).

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

Each target address has one connector, and it dials until the address leaves the
target set, waiting 100ms (`COSMOSIGNER_CONN_RETRY_WAIT`) after each failed
attempt. A port that refuses connections fails at once, so it is retried about
every 100ms; an address whose packets are still being dropped takes the full 1s
connect timeout per attempt, so it is retried about every 1.1s. A node therefore finds
a signer dialing however long it takes to start listening, and a signer that has
dropped an address stops dialing it at once instead of competing for the node's
single signer connection. `COSMOSIGNER_CONN_MAX_RETRIES`, which used to cap the
number of attempts, is still accepted but ignored; `start` prints a deprecation
warning when it is set.

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

### Graceful shutdown

On SIGINT or SIGTERM, a serving leader first resets its node connections, then transfers Raft
leadership to an up-to-date follower, waits until it observes the new leader, and exits.
`/readyz` (see [Health endpoints](#health-endpoints)) answers `503` once the signal arrives; it is
cleared alongside the handoff, not strictly before it.

The order is chosen for how CometBFT treats each outcome. Raft refuses new signing reservations on
the old leader from the moment the transfer starts, and CometBFT does not retry a request the signer
refused, so that vote would be lost. A reset connection it does retry, up to 50 attempts 100 ms apart,
each waiting for a signer to connect, and the new leader dials the node as soon as it is elected, so a request made during the handoff is
answered by the new leader. The connections are reset rather than closed because CometBFT keeps a
connection whose peer closed it and only notices at its next ping, about 3.3 seconds later.

The handoff is bounded at 5 seconds. If it fails or times out, the node has no signer for up to
that bound while this replica is still leader; shutdown then continues and the followers elect
normally once the process is gone. Keep Kubernetes `terminationGracePeriodSeconds` at its default
of 30 seconds, or at least well above 10 seconds to allow handoff and teardown. A crash or node
loss still waits for the election timeout. Single-node signers and `--initialize-only` processes
do not hand off leadership.

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

### Claiming at startup

The separate `start --initialize-only` / `claim-key` sequence suits a manually operated signer. An
orchestrator that already guarantees one owner per key (for example a Kubernetes operator that stops
every signer before a migration and reserves each consensus key for one deployment) can let `start`
write the missing claim itself:

```sh
./bin/cosmosigner start --config cosmosigner.yaml --claim-if-unclaimed
```

`start` then ensures the Raft cluster ID as usual, reads the claim, and, only when the key resource
is **unclaimed**, claims it for this cluster ID, reads it back through the runtime backend, and
continues. A claim held by another cluster is refused exactly as without the flag, and
`--initialize-only` never claims, and a corrupt or unreadable claim is reported, never replaced.
Replicas of one cluster share the same cluster ID, so repeated same-owner claims are harmless.
Vault's create-only write settles on one record; KMS labels or tags receive the same owner value.
Initial KMS claims require external serialization between owners, and AWS also requires time for
prior claims to propagate. The flag does not make an unclaimed key safe to adopt: only enable it where nothing else can be signing with
that key.

The claim uses the runtime identity unless dedicated claim credentials are supplied; they are used
for the claim only and dropped immediately afterwards:

| Backend | Claim credential | Runtime identity needs, without it |
|---|---|---|
| Vault | `--vault-claim-token-file` / `backend.vault.claim_token_file` / `COSMOSIGNER_VAULT_CLAIM_TOKEN_FILE` | `create`, `update` and `read` on `<binding_mount>/data/cluster-bindings/*`, plus `read` on `<binding_mount>/metadata/cluster-bindings/*` (already part of the runtime policy) |
| Cloud KMS | `--gcp-claim-credentials-file` / `backend.gcp.claim_credentials_file` / `COSMOSIGNER_GCP_CLAIM_CREDENTIALS_FILE` | `cloudkms.cryptoKeys.update` on the CryptoKey |
| AWS KMS | `--aws-claim-role-arn` / `backend.aws.claim_role_arn` / `COSMOSIGNER_AWS_CLAIM_ROLE_ARN` | `kms:TagResource` on the key |
| software | — | write access to the marker directory |

A dedicated claim credential needs the same access as `claim-key`: the one-shot claim policy above
for Vault (including `read` on `transit/keys/<key>` and on the binding metadata), and
`cloudkms.cryptoKeys.get`, `cloudkms.cryptoKeys.update` and `cloudkms.cryptoKeyVersions.viewPublicKey`
for Cloud KMS; for AWS KMS, `kms:GetPublicKey`, `kms:ListResourceTags` and `kms:TagResource`
on the key. With an AWS claim role, the runtime identity needs `sts:AssumeRole` on that
role instead of standing `kms:TagResource` permission. It can still assume the role
itself at any time; this is not a hard credential boundary, just as the sibling claim
credentials remain available beside the signer. Vault and Cloud KMS claim credentials
are rejected unless `claim_if_unclaimed` is enabled and they match the configured
backend. An AWS claim role is used only by the AWS startup claim path and otherwise ignored.

These claim permissions cannot delete, disable or export key material: Vault grants only reach the
binding registry, `cryptoKeys.update` changes Cloud KMS metadata, and AWS `kms:TagResource` adds or
replaces tags. They do let their holder rewrite the claim itself. Reusing the runtime identity
therefore trades that protection for a simpler setup. Use dedicated claim credentials or run
`claim-key` under an administrative identity separately where the signer should not be able to
reassign the key.

The software marker defaults to `<key file>.cosmosigner-cluster.json`, next to the key. When the key
is mounted read-only (a Kubernetes Secret), place the marker, and its lock, on writable storage with
`--binding-file` / `backend.binding_file` / `COSMOSIGNER_BINDING_FILE`. The marker records the key's
public key, so it cannot be adopted by different key material, and it must not be a symlink.
`provision` does not accept `--binding-file`, because its check against overwriting a claimed key
only sees a marker next to the key.

A relocated marker only protects what shares its storage. On per-replica storage, such as each
replica's Raft volume, it no longer stops a second deployment that mounts the same key Secret with
its own volumes: that deployment finds no marker and claims the key for its own cluster. It then
only guards each replica against a reset Raft history. With the software backend, whoever deploys
the signers must guarantee one deployment per key; the Vault, Cloud KMS and AWS KMS registries are shared and
keep protecting across deployments.

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

Existing plain-TCP deployments must choose a transport mode before upgrading.
For isolated development that will remain insecure, stage
`COSMOSIGNER_RAFT_INSECURE=true` before replacing the binary; older releases
ignore the unknown environment variable. Do not add `--raft-insecure` or YAML
`raft.insecure` until the new binary is installed because older releases reject
the unknown flag or field.

To enable mTLS, distribute the certificates and switch every replica in a
coordinated maintenance window. Plain-TCP and mTLS replicas cannot communicate,
so expect a leader election and a brief fail-closed signing pause during the
cutover.

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

## Health endpoints

Set `--http-addr` (YAML `http_addr`, env `COSMOSIGNER_HTTP_ADDR`) to a `host:port` to serve three
HTTP endpoints. The listener is disabled by default; a port that cannot be bound fails startup.

| Endpoint | Answers | Use |
|---|---|---|
| `GET /livez` | `200` whenever the process serves HTTP. | Liveness probe |
| `GET /readyz` | `200` once the Raft store is open, the key's cluster claim matches and the backend preflight has passed; `503` before that and from the start of shutdown. | Readiness probe |
| `GET /status` | `200` with a JSON description of this replica. | Diagnostics |

`/livez` is local on purpose: it does not look at the key backend or at Raft quorum, so a backend
outage or a lost quorum never makes Kubernetes restart every replica at once. The listener starts
before the backend is opened, so it also answers during a slow startup. `/readyz` is true on
followers as well as on the leader; it reports that the replica has joined and may take over, not
that it is signing. `start --initialize-only` never becomes ready.

```json
{
  "version": "3.1.0",
  "chain_id": "my-chain",
  "raft": { "node_id": "node-1", "state": "leader", "leader": true },
  "ready": true,
  "nodes": [
    { "address": "10.0.0.5:5555", "connected": true, "last_activity": "2026-10-02T10:00:00Z" }
  ]
}
```

`raft.state` is this replica's local view (`leader`, `follower`, `candidate`, `shutdown`, or
`unknown` until the Raft store is open). `nodes` lists the target addresses this replica is dialing
and is empty on a non-leader. `connected` is sampled, so it can trail the connection by a few
seconds, and `last_activity` (the last request or ping handled on that connection) is present only
while connected.

The endpoints have no authentication or TLS, so restrict the port with network policy. `/status`
is limited to what the logs already print: it never includes key material, the consensus public
key, the backend type or its coordinates, credential paths, Raft peer addresses, the cluster ID or
the signing state. There are no Prometheus metrics.

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
# Orchestrated deployments can claim an unclaimed key at startup (see "Claiming at startup"):
# export COSMOSIGNER_CLAIM_IF_UNCLAIMED=true
# Health endpoints are off unless an address is set (see "Health endpoints"):
# export COSMOSIGNER_HTTP_ADDR=0.0.0.0:8080
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
claim_if_unclaimed: false    # true lets start claim an unclaimed key (orchestrated deployments)
# http_addr: 0.0.0.0:8080    # serve /livez, /readyz and /status; disabled when unset
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
The default suite exercises the signature-determinism contract with software. AWS KMS
tests exercise the real SDK transport against a local HTTP service and the startup
detector's rejection of valid randomized signatures; they do not prove AWS determinism.
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

- Prefer a remote custody backend (`vault`, `gcpkms` or `awskms`) over `software`.
- Use private networking and firewall policy between validators, signers, raft
  peers, Vault, and KMS endpoints.
- Keep raft mTLS enabled in production; use `raft.insecure` only for isolated
  local development.
- Keep validator key files, Vault tokens, KMS credentials, raft data, and local
  test data out of source control and unaudited backups.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE).
