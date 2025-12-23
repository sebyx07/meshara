# Security Policy

## Supported Versions

Meshara is currently in early development (MVP phase). Security updates will be applied to:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Once we reach 1.0.0, we will maintain security updates for the current major version and one prior major version.

## Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

### For Security Issues

Email security reports to: **sebastian@venom.is**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Timeline**: Depends on severity
  - Critical: 1-7 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Disclosure Policy

We follow **responsible disclosure**:

1. You report the issue privately
2. We acknowledge and investigate
3. We develop and test a fix
4. We release a security patch
5. We publish a security advisory
6. You may publish your findings after the advisory

We will credit you in the security advisory unless you prefer to remain anonymous.

## Security Features

Meshara is designed with security as a core principle:

### Cryptography

- **Ed25519** for digital signatures (using `ed25519-dalek`)
- **X25519** for key exchange (using `x25519-dalek`)
- **ChaCha20-Poly1305** for authenticated encryption
- **Blake3** for cryptographic hashing
- **Argon2** for password-based key derivation

All cryptographic implementations use audited, well-established Rust crates from the RustCrypto project.

### Network Security

- **TLS 1.3** for all network communications
- **Certificate pinning** for known peers
- **Perfect forward secrecy** via ephemeral keys
- **Traffic obfuscation** to appear as HTTPS

### Secure Defaults

- All keys encrypted at rest
- No plaintext logging of sensitive data
- Memory zeroization for secrets
- Constant-time cryptographic comparisons
- Signature verification required for all messages

## Security Best Practices for Users

When using Meshara in your application:

1. **Keep dependencies updated**: Run `cargo update` regularly
2. **Use strong passphrases**: For key export/import
3. **Validate authority keys**: Only trust known authority nodes
4. **Monitor for advisories**: Watch this repository for security updates
5. **Enable security features**: Don't disable signature verification or encryption
6. **Audit your usage**: Review how you're handling keys and messages

## Security Audits

Meshara has not yet undergone a professional security audit. We plan to:

- Complete MVP development (Phases 1-5)
- Conduct internal security review
- Engage professional auditors before 1.0.0 release
- Publish audit results

**Until a professional audit is complete, Meshara should be considered experimental and not suitable for production use where security is critical.**

## Known Limitations

Current development phase limitations:

- **MVP in progress**: Not all security features implemented yet
- **No formal audit**: Has not been reviewed by security professionals
- **Active development**: API may change, introducing bugs
- **Limited testing**: Security testing is ongoing

## Cryptographic Design

See `docs/security/cryptographic-design.md` for detailed information on our cryptographic design choices and threat model.

## Bug Bounty

We do not currently offer a bug bounty program. This may change after the 1.0.0 release and security audit.

## Security-Related Issues

For non-sensitive security concerns (best practices, documentation, etc.), you may open a public issue tagged with `security`.

## Third-Party Dependencies

We carefully vet all dependencies, particularly cryptographic libraries. Key dependencies:

- `ed25519-dalek` - Ed25519 signatures
- `x25519-dalek` - X25519 key exchange
- `chacha20poly1305` - AEAD encryption
- `blake3` - Cryptographic hashing
- `rustls` - TLS implementation
- `argon2` - Password hashing

We track security advisories for all dependencies via `cargo-audit` and update promptly when vulnerabilities are disclosed.

## Security Roadmap

Planned security enhancements:

- [ ] Complete cryptographic implementation (Phase 1)
- [ ] Network layer hardening (Phase 3)
- [ ] Message authentication and replay protection (Phase 2-4)
- [ ] Authority signature verification (Phase 5)
- [ ] Traffic obfuscation (Phase 6 - optional)
- [ ] Internal security review
- [ ] Professional security audit
- [ ] Penetration testing
- [ ] Formal verification of core cryptographic code

## Contact

Security email: sebastian@venom.is
Project maintainer: sebi (sebastian@venom.is)

Thank you for helping keep Meshara secure!
