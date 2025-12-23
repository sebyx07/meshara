# Security Best Practices

Comprehensive guide to secure development, deployment, and operation of Meshara-based applications.

## For Application Developers

### Always Verify Signatures

**Critical**: Never trust unverified messages.

```rust
node.on_message_received(|event: MessageEvent| async move {
    // ALWAYS check this first
    if !event.verified {
        eprintln!("WARNING: Unverified message from {}", event.sender.to_hex());
        return; // Reject immediately
    }

    // Now safe to process
    process_message(&event.content).await;
}).await?;
```

**Why**: Prevents message forgery, injection attacks, impersonation

**Never**:
```rust
// WRONG - trusting unverified content
node.on_message_received(|event| async move {
    execute_command(&event.content); // DANGEROUS!
}).await?;
```

### Validate All Input

**Never trust message content**, even if signature verified.

```rust
node.on_message_received(|event| async move {
    if !event.verified {
        return;
    }

    // Validate before deserializing
    if event.content.len() > MAX_EXPECTED_SIZE {
        eprintln!("Message too large - possible attack");
        return;
    }

    // Safe deserialization with error handling
    match serde_json::from_slice::<SafeMessage>(&event.content) {
        Ok(msg) => {
            // Further validation
            if !is_valid_message(&msg) {
                eprintln!("Message failed validation");
                return;
            }

            process_safe_message(&msg).await;
        }
        Err(e) => {
            eprintln!("Deserialization failed: {}", e);
            // Don't crash, just log
        }
    }
}).await?;
```

**Validate**:
- Size limits (prevent memory exhaustion)
- Format (expected structure)
- Content (business logic validation)
- Range checks (numeric values)
- String sanitization (prevent injection)

### Protect Private Keys

**Never log or expose private keys**.

```rust
// GOOD - keys never leave secure storage
let node = NodeBuilder::new()
    .with_storage_path("/secure/path/")
    .with_passphrase("strong-passphrase")
    .build()
    .await?;

// WRONG - logging key material
println!("My private key: {:?}", private_key); // NEVER DO THIS
```

**Key storage requirements**:
- Encrypted at rest (use passphrase)
- Restrictive file permissions (0600 on Unix)
- Secure memory (zeroize after use)
- No swap (mlock if possible)

### Use Public Key Pinning

**Pin keys for important peers** to prevent MITM.

```rust
// Pin authority key at compile time
const OFFICIAL_AUTHORITY: &str = "7f3a2b1c..."; // Hardcoded

let authority_key = PublicKey::from_hex(OFFICIAL_AUTHORITY)?;

let node = NodeBuilder::new()
    .with_authority_keys(vec![authority_key])
    .build()
    .await?;

// Pin important peer keys
let trusted_peer = PublicKey::from_hex("9d4c1e...")?;
node.add_peer("peer.example.com:443".parse()?, Some(trusted_peer)).await?;
```

**Verify fingerprints out-of-band**:
```rust
println!("My fingerprint: {}", node.get_fingerprint());
// User verifies this via phone, in-person, etc.
```

### Implement Rate Limiting

**Prevent spam and resource exhaustion**.

```rust
let node = NodeBuilder::new()
    .enable_rate_limiting()
    .with_rate_limit(100, Duration::from_secs(60)) // 100 msg/min
    .build()
    .await?;

// Application-level rate limiting
use std::collections::HashMap;
use std::time::Instant;

let mut last_seen: HashMap<PublicKey, Instant> = HashMap::new();

node.on_message_received(move |event| {
    let mut last_seen = last_seen.clone();
    async move {
        // Rate limit per sender
        if let Some(last_time) = last_seen.get(&event.sender) {
            if last_time.elapsed() < Duration::from_secs(1) {
                eprintln!("Rate limit exceeded from {}", event.sender.to_hex());
                return;
            }
        }

        last_seen.insert(event.sender.clone(), Instant::now());

        process_message(&event.content).await;
    }
}).await?;
```

### Handle Errors Securely

**Don't leak sensitive information in errors**.

```rust
// GOOD - generic error message
match node.send_private_message(&recipient, message).await {
    Ok(msg_id) => println!("Sent: {}", msg_id),
    Err(e) => {
        eprintln!("Failed to send message");
        // Log detailed error securely (not to user)
        log::error!("Send failure: {:?}", e);
    }
}

// WRONG - leaking internal details
match decrypt_message(encrypted) {
    Err(e) => {
        // Exposing key material in error!
        println!("Decryption failed with key {:?}: {}", key, e);
    }
}
```

**Error handling principles**:
- Generic user-facing messages
- Detailed logging (secure channel only)
- No key material in errors
- No stack traces to user
- Fail securely (reject on error)

### Secure Update Verification

**Always verify updates before applying**.

```rust
node.on_update_available(|event: UpdateEvent| async move {
    // 1. Check signature
    if !event.verified {
        eprintln!("CRITICAL: Update signature invalid!");
        return;
    }

    // 2. Verify checksum
    let computed = blake3::hash(&event.package_data);
    if computed.as_bytes() != event.checksum.as_slice() {
        eprintln!("CRITICAL: Checksum mismatch - corrupted or tampered!");
        return;
    }

    // 3. Check version compatibility
    if !is_compatible_version(&event.version, &event.required_version) {
        eprintln!("Update incompatible with current version");
        return;
    }

    // 4. Human review (don't auto-install critical systems)
    println!("Update v{} available", event.version);
    println!("Changelog:\n{}", event.changelog);

    if user_approves_update(&event) {
        // 5. Backup before applying
        backup_current_state().await;

        // 6. Apply update
        match apply_update(&event.package_data).await {
            Ok(_) => println!("✓ Update applied"),
            Err(e) => {
                eprintln!("✗ Update failed: {}", e);
                restore_backup().await;
            }
        }
    }
}).await?;
```

### Minimize Attack Surface

**Disable unnecessary features**.

```rust
// Production deployment - minimal features
let node = NodeBuilder::new()
    .with_network_profile(NetworkProfile::Standard)
    .disable_mdns()  // Don't need local discovery
    .disable_dev_mode()  // Never in production
    .with_max_peers(50)  // Limit connections
    .build()
    .await?;
```

**Don't**:
- Enable dev-mode in production
- Expose internal APIs publicly
- Run with elevated privileges
- Accept all incoming connections

### Use Secure Defaults

**Don't weaken security for convenience**.

```rust
// GOOD - secure defaults
let node = NodeBuilder::new()
    .with_privacy_level(PrivacyLevel::Enhanced) // Not Minimum
    .with_passphrase("strong-passphrase") // Not empty
    .enable_rate_limiting() // Prevent abuse
    .build()
    .await?;

// WRONG - weakening security
let node = NodeBuilder::new()
    .with_privacy_level(PrivacyLevel::Minimum)
    .disable_signature_verification() // NEVER DO THIS
    .with_passphrase("") // Weak protection
    .build()
    .await?;
```

## For Node Operators

### Secure Key Management

**Protect authority private keys**.

**Best practices**:
1. **Hardware Security Module (HSM)**: Store keys in HSM, not on disk
2. **Air-gapped signing**: Sign on offline machine, transfer signatures
3. **Multi-party computation**: Split key across multiple parties
4. **Key ceremony**: Document key generation process
5. **Backup securely**: Encrypted backups in multiple locations

**Air-gapped signing example**:
```bash
# On secure offline machine
1. Load key from HSM
2. Sign update package
3. Export signature to USB

# On online machine
4. Import signature
5. Publish update with signature
```

### Operational Security

**Run authority nodes securely**.

**Infrastructure**:
- Dedicated servers (not shared)
- Minimal OS (reduce attack surface)
- Firewall (allow only necessary ports)
- Intrusion detection (monitor for attacks)
- Audit logging (track all operations)
- Regular updates (security patches)
- Monitoring (uptime, performance, anomalies)

**Access control**:
- Multi-factor authentication (MFA)
- Least privilege (minimal permissions)
- Key rotation (periodic)
- Access logs (audit trail)
- Separate duties (no single person with full access)

### Network Security

**Secure network configuration**.

```rust
let node = NodeBuilder::new()
    .with_listen_port(443) // Standard HTTPS
    .with_bind_address("0.0.0.0:443".parse()?) // Public
    .with_max_peers(500) // High for bridge nodes
    .enable_http2_framing() // HTTPS mimicry
    .build()
    .await?;
```

**Firewall rules**:
```bash
# Allow incoming connections on 443
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow outgoing connections
iptables -A OUTPUT -p tcp --sport 443 -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
```

### Monitoring and Alerting

**Detect anomalies and attacks**.

```rust
use prometheus::{Counter, Gauge, Histogram};

// Metrics
let messages_received = Counter::new("messages_received", "Total messages received").unwrap();
let active_connections = Gauge::new("active_connections", "Number of active peer connections").unwrap();
let message_latency = Histogram::new("message_latency", "Message processing latency").unwrap();

node.on_message_received(move |event| {
    messages_received.inc();
    // ... process message
}).await?;

// Alert on anomalies
if active_connections.get() < 10 {
    alert("Low peer count - possible network issue");
}

if messages_received.get() > 10000 {
    alert("High message rate - possible DoS");
}
```

**What to monitor**:
- Peer count (detect eclipse attack)
- Message rate (detect DoS)
- Failed signature verifications (detect forgery attempts)
- Resource usage (CPU, memory, bandwidth)
- Error rates (detect bugs or attacks)
- Geographic distribution (detect concentration)

### Incident Response

**Plan for security incidents**.

**Incident response plan**:
1. **Detect**: Monitor for suspicious activity
2. **Assess**: Determine scope and severity
3. **Contain**: Isolate affected systems
4. **Eradicate**: Remove malicious code/access
5. **Recover**: Restore normal operation
6. **Learn**: Post-mortem and improvements

**Authority key compromise response**:
```rust
// 1. Immediately revoke compromised key
node.remove_authority(&compromised_key).await?;

// 2. Generate new key (secure process)
let new_authority_key = generate_new_authority_key_securely();

// 3. Announce key rotation
announce_key_rotation(&old_key, &new_authority_key);

// 4. Add new key to clients
node.add_authority(new_authority_key, "Rotated Authority".to_string(), TrustLevel::UpdateAuthority).await?;

// 5. Transition period (accept both keys)
tokio::time::sleep(Duration::from_secs(30 * 24 * 3600)).await; // 30 days

// 6. Remove old key completely
```

## For Security Researchers

### Responsible Disclosure

**Report vulnerabilities responsibly**.

**Process**:
1. Find vulnerability
2. Document PoC (proof of concept)
3. Email security team: security@meshara.example.com
4. Encrypt with PGP (if sensitive)
5. Wait for acknowledgment (48 hours)
6. Coordinate disclosure timeline
7. Public disclosure after fix

**What to include**:
- Vulnerability description
- Affected versions
- Proof of concept code
- Suggested fix (optional)
- Impact assessment

### Bug Bounty

**Rewards for finding vulnerabilities**:
- Critical (RCE, key compromise): $5,000 - $20,000
- High (authentication bypass, DoS): $1,000 - $5,000
- Medium (information disclosure): $500 - $1,000
- Low (minor issues): $100 - $500

**Scope**:
- Meshara library code
- Protocol design
- Cryptographic implementation
- Network stack

**Out of scope**:
- Social engineering
- Physical attacks
- DoS (if no permanent impact)
- Third-party dependencies

### Security Audits

**Request code audit** before production deployment.

**Focus areas**:
- Cryptographic implementation (correct usage of primitives)
- Protocol design (no logic flaws)
- Input validation (prevent injection)
- Memory safety (Rust helps, but verify unsafe code)
- Concurrency (race conditions, deadlocks)

**Auditors**: Engage reputable security firms (Trail of Bits, NCC Group, Cure53)

## Security Checklist

### Pre-Deployment

- [ ] Code review completed
- [ ] Security audit performed
- [ ] All tests passing (unit, integration, security)
- [ ] Dependencies up-to-date (no known vulnerabilities)
- [ ] Secrets not hardcoded
- [ ] Logging configured (no sensitive data logged)
- [ ] Error handling reviewed (no information leakage)
- [ ] Rate limiting enabled
- [ ] Resource limits configured
- [ ] Monitoring set up
- [ ] Incident response plan documented
- [ ] Backup strategy in place

### Post-Deployment

- [ ] Monitor metrics dashboards
- [ ] Review logs regularly
- [ ] Apply security updates promptly
- [ ] Rotate keys periodically
- [ ] Test backups (verify restoration)
- [ ] Conduct security drills
- [ ] Stay informed (security advisories)
- [ ] Re-audit after major changes

### For Each Release

- [ ] Security-focused code review
- [ ] Regression testing
- [ ] Dependency updates
- [ ] Changelog reviewed
- [ ] Signed release (GPG/PGP)
- [ ] Release notes include security fixes
- [ ] Gradual rollout (canary deployment)
- [ ] Monitor for issues post-release

## Common Pitfalls to Avoid

### 1. Trusting User Input

**Wrong**:
```rust
let command = String::from_utf8_lossy(&event.content);
std::process::Command::new("sh").arg("-c").arg(command).spawn(); // Command injection!
```

**Right**:
```rust
// Validate and sanitize
match parse_safe_command(&event.content) {
    Ok(cmd) => execute_safe_command(cmd),
    Err(_) => eprintln!("Invalid command"),
}
```

### 2. Weak Passphrases

**Wrong**:
```rust
node.with_passphrase("password123") // Weak!
```

**Right**:
```rust
// Enforce strong passphrases
fn validate_passphrase(passphrase: &str) -> bool {
    passphrase.len() >= 12 &&
    passphrase.chars().any(|c| c.is_uppercase()) &&
    passphrase.chars().any(|c| c.is_lowercase()) &&
    passphrase.chars().any(|c| c.is_numeric()) &&
    passphrase.chars().any(|c| !c.is_alphanumeric())
}
```

### 3. Ignoring Errors

**Wrong**:
```rust
node.send_private_message(&recipient, message).await.unwrap(); // Panics on error!
```

**Right**:
```rust
match node.send_private_message(&recipient, message).await {
    Ok(msg_id) => println!("Sent: {}", msg_id),
    Err(e) => {
        eprintln!("Send failed: {}", e);
        // Handle error appropriately
    }
}
```

### 4. Logging Sensitive Data

**Wrong**:
```rust
log::debug!("Received message: {:?} from {:?}", message_content, sender);
```

**Right**:
```rust
log::debug!("Received message from {}", sender.to_hex()[..8]); // Only partial ID
// Don't log content
```

### 5. Disabling Security Features

**Wrong**:
```rust
node.disable_signature_verification(); // NEVER!
node.disable_rate_limiting(); // Vulnerable to DoS
```

**Right**:
```rust
// Use secure defaults, only override if absolutely necessary and documented
```

### 6. Hardcoding Secrets

**Wrong**:
```rust
const API_KEY: &str = "sk_live_abc123..."; // In source code!
```

**Right**:
```rust
let api_key = std::env::var("API_KEY")?; // From environment
// Or use secret management service
```

### 7. Insufficient Input Validation

**Wrong**:
```rust
let path = String::from_utf8_lossy(&event.content);
std::fs::read(&path)?; // Path traversal!
```

**Right**:
```rust
let filename = String::from_utf8_lossy(&event.content);
// Validate: no path separators, limited charset
if !is_safe_filename(&filename) {
    return Err("Invalid filename");
}
let path = safe_base_dir.join(&filename); // Constrain to directory
std::fs::read(&path)?;
```

## Resources

**Security documentation**:
- [Cryptographic Design](cryptographic-design.md)
- [Threat Model](threat-model.md)

**External resources**:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [Secure Coding Practices](https://www.securecoding.cert.org/)

**Reporting**:
- Email: security@meshara.example.com
- PGP Key: [Fingerprint]
- Bug Bounty: https://meshara.example.com/security/bounty
