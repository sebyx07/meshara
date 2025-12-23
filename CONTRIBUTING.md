# Contributing to Meshara

Thank you for your interest in contributing to Meshara! This document provides guidelines and information for contributors.

## Code of Conduct

Be respectful, constructive, and professional. We're building secure communication tools that protect people's privacy - this is serious work that deserves thoughtful collaboration.

## How to Contribute

### Reporting Bugs

- Check if the bug has already been reported in Issues
- Include detailed reproduction steps
- Provide your environment (OS, Rust version, etc.)
- For security vulnerabilities, see SECURITY.md - do NOT open a public issue

### Suggesting Features

- Open an issue describing the feature and use case
- Explain how it aligns with Meshara's goals (privacy, decentralization, developer-friendliness)
- Be open to discussion - we may suggest alternative approaches

### Contributing Code

1. **Fork the repository** and create a feature branch
2. **Write tests** for your changes - we maintain high test coverage
3. **Follow the coding standards** (see below)
4. **Document your code** - public APIs need documentation
5. **Run the test suite** and ensure everything passes
6. **Submit a pull request** with a clear description

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/meshara.git
cd meshara

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install protobuf compiler
# On Ubuntu/Debian:
sudo apt-get install protobuf-compiler

# On macOS:
brew install protobuf

# Build the project
cargo build

# Run tests
cargo test

# Run clippy (linter)
cargo clippy -- -D warnings

# Format code
cargo fmt
```

## Coding Standards

### General Principles

- **Security first**: Never compromise security for convenience
- **No panics in library code**: Always return `Result` for fallible operations
- **Use audited crates**: Never implement crypto primitives yourself
- **Test thoroughly**: Unit tests + integration tests for all features
- **Document public APIs**: Users need to understand how to use your code

### Rust Style

- Follow the Rust API Guidelines: https://rust-lang.github.io/api-guidelines/
- Use `rustfmt` for formatting (run `cargo fmt`)
- Address all `clippy` warnings (run `cargo clippy`)
- Use meaningful variable names (no single-letter names except loop counters)
- Add comments explaining *why*, not *what* (code should be self-documenting)

### Commit Messages

- Use present tense ("Add feature" not "Added feature")
- First line: brief summary (max 50 chars)
- Blank line, then detailed explanation if needed
- Reference issues/PRs where relevant

Example:
```
Add X25519 key exchange for encryption

Implements the key exchange mechanism using x25519-dalek for
deriving shared secrets between peers. This is used in the
encryption module for end-to-end encrypted messages.

Closes #42
```

### Testing Requirements

- **Unit tests**: Test individual functions/modules in isolation
- **Integration tests**: Test feature workflows end-to-end
- **Security tests**: Test that invalid inputs are rejected, signatures fail when modified, etc.
- **No `unwrap()` in tests**: Use `expect()` with descriptive messages or proper error handling

### Documentation

- All public functions must have doc comments (`///`)
- Include examples in doc comments where helpful
- Update README.md if adding user-facing features
- Add entries to CHANGELOG.md for notable changes

## Security Considerations

When contributing code that touches cryptography, networking, or message handling:

- **Review security best practices** in docs/security/
- **Use constant-time operations** for cryptographic comparisons
- **Zeroize sensitive data** after use (use the `zeroize` crate)
- **Validate all inputs** from the network or users
- **Never log sensitive data** (private keys, plaintexts, etc.)
- **Get review from maintainers** before merging crypto code

## Pull Request Process

1. Ensure your PR addresses a single concern (feature, bug fix, etc.)
2. Update documentation as needed
3. Add tests for your changes
4. Ensure CI passes (formatting, clippy, tests)
5. Request review from maintainers
6. Address review feedback
7. Maintainers will merge once approved

## Branch Strategy

- `main`: Stable, always buildable, deployable
- Feature branches: `feature/your-feature-name`
- Bug fixes: `fix/issue-description`
- Keep branches focused and short-lived

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Open a Discussion on GitHub
- Ask in Issues (for implementation questions)
- See docs/ for architecture and design documentation

Thank you for contributing to Meshara!
