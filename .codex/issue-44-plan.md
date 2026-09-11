## Root Cause / Goal

`KeyBackend.Sign` does not state the signature-determinism requirement that the
Raft reservation/commit path relies on. Overlapping requests may sign the same
reserved bytes independently, while duplicate commits accept only byte-identical
signatures. The current backends are expected to satisfy that invariant, but the
contract and backend-wide regression evidence are missing.

## Approach

1. Document on `KeyBackend.Sign` that the same consensus key and sign bytes must
   produce the same raw Ed25519 signature, including retries and overlapping calls
   through separate backend instances. State why reservation retries require it and
   that a backend unable to satisfy it needs a different reservation design.
2. Add a shared backend conformance helper that signs fixed non-consensus inputs,
   checks signature length and validity, preserves an independent baseline copy,
   then checks bounded sequential and concurrent signing for byte equality.
3. Invoke the helper for the software backend and from the real Vault and GCP KMS
   integration tests. Keep provider tests opt-in and describe the GCP result as
   evidence for the configured key version and protection level only.
4. Document the determinism contract and how default versus provider integration
   coverage runs in the README.
5. Build, vet, run the backend tests and full race suite, compile both integration
   variants, exercise an isolated local Vault, and report GCP KMS as skipped unless
   designated test credentials are available.

## Critical Files

- `internal/backend/backend.go` — make signature determinism part of the interface contract.
- `internal/backend/backend_test.go` — shared conformance helper and software coverage.
- `internal/backend/vault_integration_test.go` — Vault conformance invocation.
- `internal/backend/gcpkms_integration_test.go` — GCP KMS conformance invocation.
- `README.md` — architecture rationale and test commands.

Read-only context: `internal/state/fsm.go`, `internal/signer/privval.go`,
`.github/workflows/test.yml`, and `scripts/vault-dev.sh`.

## Risks & Side Effects

- No runtime behavior, interface signature, Raft protocol, dependency, or deployment
  change is intended.
- Equality alone could accept deterministic invalid output, so the helper must also
  verify length and signature validity.
- Copy the baseline signature before retrying so an implementation that reuses a
  mutable buffer cannot create a false pass.
- Concurrent assertions must run in the test goroutine, not worker goroutines.
- Provider tests create or use test resources. Use an isolated Vault and a designated
  KMS test key; never use a validator key for conformance testing.
- Provider integration tags are not run by current CI, so compilation and skipped
  tests must not be reported as live provider evidence.

## Scope

Files: 5 | Lines: approximately 120-170 | Complexity: medium

## Verification

- `go test ./internal/backend -count=1`
- `go build ./...`
- `go vet ./...`
- `go test -race ./...`
- `go test -tags 'vault_integration gcpkms_integration' ./internal/backend -run '^$'`
- Isolated Vault: `go test -race -tags vault_integration ./internal/backend -run TestVaultIntegration_SignDeterminism -count=1 -v`
- Designated KMS key, when available: `go test -race -tags gcpkms_integration ./internal/backend -run TestGCPKMS_SignVerify -count=1 -v`

## Out of Scope

- Changing the reservation/commit protocol.
- Adding a backend that cannot provide deterministic Ed25519 signatures.
- Provisioning persistent Vault or GCP KMS CI infrastructure.
