## Summary

<!-- What changed and why? -->

## Risk model

<!-- Required for signing, key custody, raft, networking, config precedence, or release changes. Otherwise write N/A. -->

## Testing

<!-- Commands run, for example: make vet; make test-cover; make lint -->

## Documentation

<!-- README/examples/config docs updated? If not needed, say why. -->

## Security checklist

- [ ] No secrets, validator private keys, Vault tokens, cloud credentials, or private infrastructure details are included.
- [ ] Errors/logs do not expose secret material.
- [ ] Security-sensitive config fails closed instead of silently downgrading.
- [ ] Public docs/examples use placeholders only.
