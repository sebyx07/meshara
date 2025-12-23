# Cryptographic Design

Detailed specification of Meshara's cryptographic architecture, algorithms, and security properties.

## Design Goals

1. **End-to-end encryption**: Only sender and recipient can read message content
2. **Forward secrecy**: Compromise of long-term keys doesn't reveal past messages
3. **Authentication**: Prove sender identity and message integrity
4. **Deniability** (not provided): Signatures prove sender identity
5. **Post-quantum resistance** (future): Current algorithms vulnerable to quantum computers

## Cryptographic Primitives

### Ed25519 (Signatures)

**Purpose**: Message signing and identity verification

**Algorithm**: EdDSA with Curve25519

**Security level**: 128-bit (equivalent to 3072-bit RSA)

**Key sizes**:
- Private key: 32 bytes
- Public key: 32 bytes
- Signature: 64 bytes

**Implementation**: `ed25519-dalek` crate

**Properties**:
- Deterministic signatures
- No random number generation required
- Fast verification (~20,000 sig/sec)
- Collision-resistant

**Usage in Meshara**:
```
Identity = Ed25519 keypair
Message signature = Ed25519.sign(private_key, message)
Verification = Ed25519.verify(public_key, message, signature)
```

### X25519 (Key Exchange)

**Purpose**: Derive shared secrets for encryption

**Algorithm**: ECDH with Curve25519

**Security level**: 128-bit

**Key sizes**:
- Private key: 32 bytes
- Public key: 32 bytes
- Shared secret: 32 bytes

**Implementation**: `x25519-dalek` crate

**Properties**:
- Constant-time (timing attack resistant)
- Small keys
- Fast computation
- Malleable (not used for direct encryption)

**Usage in Meshara**:
```
Ephemeral_key = X25519.generate()
Shared_secret = X25519.dh(ephemeral_private, recipient_public)
Encryption_key = HKDF(shared_secret, "meshara-message-encryption-v1")
```

### ChaCha20-Poly1305 (AEAD)

**Purpose**: Authenticated encryption

**Algorithm**: ChaCha20 stream cipher + Poly1305 MAC

**Security level**: 256-bit

**Key size**: 32 bytes
**Nonce size**: 12 bytes (96 bits)
**Tag size**: 16 bytes (128 bits)

**Implementation**: `chacha20poly1305` crate

**Properties**:
- AEAD (Authenticated Encryption with Associated Data)
- Fast (~2 GB/sec per core)
- Constant-time
- IND-CCA2 secure
- Prevents tampering and forgery

**Usage in Meshara**:
```
Cipher = ChaCha20Poly1305(key)
Ciphertext || Tag = Cipher.encrypt(nonce, plaintext)
Plaintext = Cipher.decrypt(nonce, ciphertext || tag)
```

**Nonce handling**:
- Random nonce generation (96 bits)
- Collision probability: negligible (2^48 messages)
- Never reuse nonce with same key
- Ephemeral keys ensure nonce uniqueness

### Blake3 (Hashing)

**Purpose**: Message IDs, checksums, key derivation

**Algorithm**: Cryptographic hash function

**Output size**: 256 bits (32 bytes)

**Implementation**: `blake3` crate

**Properties**:
- Extremely fast (~10 GB/sec)
- Parallel computation
- Collision-resistant
- Preimage-resistant
- Supports keyed hashing and KDF mode

**Usage in Meshara**:
```
Message_ID = Blake3(serialized_message)
Checksum = Blake3(update_package)
Fingerprint = Blake3(public_key)
```

### Argon2 (Password Hashing)

**Purpose**: Derive encryption keys from passphrases

**Algorithm**: Memory-hard password hash

**Implementation**: `argon2` crate

**Parameters**:
- Memory: 64 MiB
- Iterations: 3
- Parallelism: 4
- Salt: 32 bytes (random)

**Properties**:
- GPU-resistant
- ASIC-resistant
- Configurable resource usage
- Winner of Password Hashing Competition

**Usage in Meshara**:
```
Salt = random(32 bytes)
Key = Argon2(passphrase, salt, mem=64MiB, time=3)
Encrypted_keys = ChaCha20Poly1305(Key).encrypt(identity_keys)
```

## Protocol Design

### Message Encryption Flow

**Sender side**:

1. **Generate ephemeral keypair**: `(e_priv, e_pub) = X25519.generate()`

2. **Perform key exchange**:
   ```
   shared_secret = X25519.dh(e_priv, recipient_public_static)
   ```

3. **Derive encryption key**:
   ```
   hkdf = HKDF-SHA256(salt=none, ikm=shared_secret)
   encryption_key = hkdf.expand("meshara-message-encryption-v1", 32)
   ```

4. **Generate random nonce**: `nonce = random(12 bytes)`

5. **Encrypt content**:
   ```
   cipher = ChaCha20Poly1305(encryption_key)
   ciphertext || tag = cipher.encrypt(nonce, plaintext)
   ```

6. **Create payload**:
   ```
   payload = {
     ephemeral_public_key: e_pub,
     nonce: nonce,
     ciphertext: ciphertext || tag
   }
   ```

7. **Serialize payload**: `payload_bytes = protobuf.encode(payload)`

8. **Sign payload**: `signature = Ed25519.sign(sender_private_key, payload_bytes)`

9. **Create message**:
   ```
   message = {
     sender_public_key: sender_public_static,
     payload: payload_bytes,
     signature: signature,
     timestamp: current_time(),
     message_id: Blake3(payload_bytes)
   }
   ```

**Recipient side**:

1. **Verify signature**:
   ```
   Ed25519.verify(message.sender_public_key, message.payload, message.signature)
   ```

2. **Deserialize payload**: `payload = protobuf.decode(message.payload)`

3. **Perform key exchange**:
   ```
   shared_secret = X25519.dh(recipient_private_static, payload.ephemeral_public_key)
   ```

4. **Derive decryption key** (same as encryption key):
   ```
   hkdf = HKDF-SHA256(salt=none, ikm=shared_secret)
   decryption_key = hkdf.expand("meshara-message-encryption-v1", 32)
   ```

5. **Decrypt content**:
   ```
   cipher = ChaCha20Poly1305(decryption_key)
   plaintext = cipher.decrypt(payload.nonce, payload.ciphertext)
   ```

### Broadcast Signing Flow

Broadcasts are signed but NOT encrypted (public by design).

**Sender side**:

1. **Create broadcast payload**: `payload = {content, content_type, metadata}`

2. **Serialize**: `payload_bytes = protobuf.encode(payload)`

3. **Sign**: `signature = Ed25519.sign(sender_private_key, payload_bytes)`

4. **Create message**:
   ```
   message = {
     sender_public_key: sender_public_static,
     payload: payload_bytes,
     signature: signature,
     timestamp: current_time(),
     message_id: Blake3(payload_bytes)
   }
   ```

**Recipient side**:

1. **Verify signature**:
   ```
   Ed25519.verify(message.sender_public_key, message.payload, message.signature)
   ```

2. **Deserialize and process**: Content is plaintext

## Security Properties

### Confidentiality

**Private messages**:
- ✅ End-to-end encryption (only sender and recipient can read)
- ✅ TLS provides additional transport encryption
- ✅ Ephemeral keys provide forward secrecy

**Broadcast messages**:
- ❌ NOT encrypted (by design - public messages)
- ✅ TLS encrypts during transport

**Network metadata**:
- ❌ Sender IP visible to first hop
- ❌ Recipient IP visible to last hop
- ❌ Message timing visible to network observers
- ✅ Onion routing hides sender/recipient (if enabled)

### Authentication

**Message authenticity**:
- ✅ Ed25519 signatures prove sender identity
- ✅ Poly1305 MAC prevents tampering
- ✅ Public key is verified identity

**Peer authenticity**:
- ✅ TLS certificates based on public keys
- ✅ Ed25519 signatures in protocol handshake
- ⚠️  No PKI - trust on first use (TOFU)

### Integrity

- ✅ AEAD encryption (ChaCha20-Poly1305) detects tampering
- ✅ Ed25519 signatures detect message modification
- ✅ Blake3 checksums for update packages

**Any tampering results in**:
- Signature verification failure (message rejected)
- AEAD decryption failure (message rejected)
- Checksum mismatch (update rejected)

### Forward Secrecy

**Provided by**: Ephemeral X25519 keys per message

**Guarantee**: Compromise of long-term private key does NOT reveal:
- Past message contents
- Past encryption keys
- Past shared secrets

**Only reveals**:
- Future messages (can be decrypted)
- Current ongoing sessions

**Does NOT provide post-compromise security**: Compromise persists until key rotation

### Non-Repudiation

**Property**: Sender cannot deny sending message

**Mechanism**: Ed25519 signatures are:
- Unique to private key
- Deterministic (same message = same signature)
- Publicly verifiable

**Limitation**: No deniability (unlike OTR or Signal)

## Attack Resistance

### Man-in-the-Middle (MITM)

**Protection**:
- Public key pinning (optional)
- TLS certificate verification
- Out-of-band key verification (fingerprints)

**Vulnerability without pinning**:
- First connection susceptible (TOFU)
- Recommend: Verify fingerprints out-of-band

### Replay Attacks

**Protection**:
- Timestamps in messages
- Bloom filter deduplication (message IDs)
- Nonce uniqueness (ephemeral keys ensure this)

**Replay window**: 5 minutes (configurable)

### Sybil Attacks

**Partial protection**:
- Peer reputation scoring
- Connection limits per peer
- Rate limiting

**Vulnerability**: Network is permissionless - anyone can join

### Traffic Analysis

**Limited protection**:
- ✅ TLS hides content from network observers
- ✅ Padding obscures message sizes
- ❌ Timing patterns still visible
- ❌ Message sizes approximate (despite padding)
- ✅ Onion routing hides sender/recipient correlation

### Denial of Service (DoS)

**Protections**:
- Rate limiting (per-peer message limits)
- Connection limits (max concurrent connections)
- Signature verification before processing (cheap operation)
- Resource limits (max message size, max hop count)

**Vulnerability**: Gossip amplification (broadcasts consume bandwidth)

### Eclipse Attacks

**Protection**:
- Multiple bootstrap nodes
- DHT for decentralized peer discovery
- Peer diversity (connect to varied peers)

**Vulnerability**: Attacker controlling all bootstrap nodes can isolate victim

## Key Management

### Key Generation

**Entropy source**: OS-provided CSPRNG (`OsRng`)

**Process**:
1. Generate Ed25519 keypair: `ed25519_dalek::Keypair::generate(&mut OsRng)`
2. Generate X25519 keypair: `x25519_dalek::StaticSecret::random_from_rng(&mut OsRng)`
3. Derive node ID: `Blake3(ed25519_public_key)`

**Randomness quality**: Critical for security
- Uses `/dev/urandom` (Linux)
- Uses `CryptGenRandom` (Windows)
- Uses `arc4random` (macOS)

### Key Storage

**At rest encryption**:
```
User passphrase
    ↓ Argon2 (64MiB, 3 iter)
    ↓
Encryption key (32 bytes)
    ↓ ChaCha20-Poly1305
    ↓
Encrypted private keys
    ↓ Store to disk
```

**File format**:
```
┌─────────────────────────────────────┐
│ Salt (32 bytes)                     │
│ Argon2 params (memory, time, para) │
│ Nonce (12 bytes)                    │
│ Encrypted ed25519 key (64 bytes)   │
│ Encrypted x25519 key (32 bytes)    │
│ Poly1305 tag (16 bytes)             │
└─────────────────────────────────────┘
```

### Key Rotation

**Current status**: Not implemented

**Future design**:
1. Generate new keypair
2. Sign new public key with old private key
3. Broadcast rotation message
4. Accept messages to both old and new keys (transition period)
5. After transition, reject old key

**Migration period**: 30 days recommended

## Cryptographic Guarantees

### What Meshara Provides

1. **IND-CCA2 security**: Chosen-ciphertext attack resistance
2. **EUF-CMA security**: Existential unforgeability under chosen-message attack
3. **Forward secrecy**: Past messages safe if key compromised
4. **Message authentication**: Prove sender identity
5. **Message integrity**: Detect tampering
6. **Confidentiality**: Only intended recipient can read

### What Meshara Does NOT Provide

1. **Post-quantum security**: Vulnerable to quantum computers
2. **Deniability**: Signatures prove sender
3. **Traffic analysis resistance**: Without onion routing
4. **Metadata privacy**: Message timing, sizes visible
5. **Anonymity**: IP addresses visible (without Tor/VPN)
6. **Post-compromise security**: No automatic recovery from key compromise

## Security Levels

**Symmetric encryption**: 256-bit (ChaCha20)
**Asymmetric encryption**: 128-bit equivalent (Curve25519)
**Signatures**: 128-bit equivalent (Ed25519)
**Hash functions**: 256-bit (Blake3)

**Effective security level**: 128-bit (limited by asymmetric crypto)

**Quantum security**: 0-bit (all algorithms vulnerable to Shor's algorithm)

## Compliance and Standards

**Algorithms**:
- ✅ NIST-approved (ChaCha20-Poly1305 in RFC 7539)
- ✅ IETF standards (Ed25519 in RFC 8032)
- ✅ Widely audited implementations (RustCrypto)

**Not FIPS 140-2 compliant**: Uses Curve25519 (not NIST curve)

## Future Improvements

**Post-quantum cryptography**:
- CRYSTALS-Kyber (key exchange)
- CRYSTALS-Dilithium (signatures)
- Hybrid mode (classical + post-quantum)

**Enhanced privacy**:
- Padmé (padding for metadata resistance)
- Cover traffic (dummy messages)
- Mix networks (Loopix-style)

**Key compromise recovery**:
- Signal-style ratcheting
- Post-compromise security

**Hardware security**:
- TPM integration
- Secure enclave support
- Hardware security module (HSM) support
