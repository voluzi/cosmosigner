# Contributing to Cosmosigner

Thanks for helping improve Cosmosigner.

Cosmosigner is security-sensitive validator infrastructure. Keep changes small, explicit, tested, and easy to review.

## Development Requirements

- Go version from `go.mod`.
- `make`.
- Optional: Docker for Vault development and integration tests.
- Optional: `golangci-lint` for `make lint`.

## Local Workflow

```sh
git clone https://github.com/voluzi/cosmosigner.git
cd cosmosigner

go mod download
make test
make vet
make build
```

Before opening a pull request, run:

```sh
make vet
make test-cover
```

If `golangci-lint` is installed, also run:

```sh
make lint
```

## Integration Tests

Integration tests are opt-in and require external services or cloud credentials.

### Vault

For a disposable local Vault development server:

```sh
scripts/vault-dev.sh up
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
  go test -tags vault_integration -run Vault ./internal/backend/
scripts/vault-dev.sh down
```

The `root` token above is the disposable token from Vault dev mode. Never use a
production Vault token in examples, issue reports, or commits.

### Google Cloud KMS

Use an existing test key version and Application Default Credentials or a credentials file:

```sh
GCP_KMS_KEY_VERSION=projects/.../cryptoKeyVersions/1 \
  go test -tags gcpkms_integration -run GCPKMS ./internal/backend/
```

### AWS KMS

The default suite uses a local HTTP KMS service with the real AWS SDK; it needs no
credentials or cloud resources. Real signing uses a dedicated single-Region Ed25519
key and the standard AWS credential/region chains:

```sh
AWS_REGION=eu-west-1 AWS_KMS_KEY_ID='<dedicated-test-key-arn>' \
  go test -race -tags awskms_integration -run TestAWSKMSIntegrationSignDeterminism ./internal/backend/
```

The import drill requires explicit opt-in. It creates a billable EXTERNAL key and
schedules deletion (seven-day waiting period) on test completion, including failures
once the key ARN is known:

```sh
AWS_REGION=eu-west-1 AWS_KMS_IMPORT_TEST=1 \
  go test -race -tags awskms_integration -run TestAWSKMSIntegrationImportRoundTrip ./internal/backend/
```

Use a disposable account/role with the permissions listed in the
[README](README.md#aws-kms-backend). Run both drills before deploying this backend;
local transport tests cannot establish AWS determinism or acceptance of Ed25519 PKCS#8 imports.
Retain protected recovery material for real imported keys, as required by AWS.

Do not commit credentials, real validator keys, generated token files, raft data, or local test data.

## Pull Request Guidelines

- Explain the risk model for changes that affect signing, key custody, raft, networking, or configuration precedence.
- Add or update tests for behavior changes.
- Update `README.md`, examples, and flags/config documentation when user-facing behavior changes.
- Keep generated files and unrelated formatting churn out of the PR.
- Prefer clear errors over silent fallback for security-sensitive configuration.

## Commit Messages

Use concise, imperative commit messages. Conventional Commits are welcome, for example:

- `feat: add aws kms backend`
- `fix: reject partial raft tls configuration`
- `docs: document vault token renewal`

## Reporting Security Issues

Do not report security vulnerabilities in public issues. See [`SECURITY.md`](SECURITY.md).
