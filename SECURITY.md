# Security Policy

Cosmosigner handles validator signing material and double-sign protection. Please treat potential vulnerabilities as sensitive.

## Supported Versions

Security fixes are provided for the latest released version. If you are running from source, use the latest commit on `main` or a tagged release that includes the relevant fix.

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for suspected security vulnerabilities.

Report vulnerabilities through one of these channels:

1. GitHub private vulnerability reporting, if enabled for this repository.
2. Email <security@voluzi.com> with enough detail to reproduce or assess the issue.

Helpful report details:

- Affected version or commit.
- Deployment mode and backend (`software`, `vault`, or `gcpkms`).
- Impact, especially whether the issue can cause key exposure, double-signing, unauthorized signing, denial of signing, or cluster takeover.
- Reproduction steps, proof of concept, logs, and relevant configuration with secrets redacted.

We aim to acknowledge reports within 2 business days and provide a remediation plan or status update within 7 business days.

## Scope

In scope:

- Key custody or key import weaknesses.
- Double-sign protection bypasses.
- Raft quorum, membership, or transport security issues.
- Remote signer protocol issues that allow unauthorized signing or denial of signing.
- Secret leakage through logs, errors, builds, or release artifacts.

Out of scope:

- Issues that require access to intentionally local-only development tooling.
- Denial-of-service reports without a plausible production impact.
- Vulnerabilities in third-party services such as Vault, Google Cloud KMS, or CometBFT unless Cosmosigner uses them unsafely.

## Operational Security Notes

- Do not use the `software` backend for production validators unless you explicitly accept in-process key custody.
- Protect the node-to-signer network path with private networking and firewall policy.
- Use raft mTLS (`raft.tls_cert`, `raft.tls_key`, `raft.tls_ca`) whenever signer replicas communicate over an untrusted network.
- Keep Vault tokens, KMS credentials, imported key files, and raft data directories out of source control and backups that are not access-controlled.
