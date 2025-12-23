# Cryptography Architecture

Meshara's cryptographic design provides end-to-end encryption, message authentication, and identity management. All cryptographic primitives use audited implementations from the RustCrypto ecosystem.

## Cryptographic Primitives

### Ed25519 Signatures

**Purpose**: Message signing and identity.

**Properties**:
- 256-bit security level
- 32-byte public keys
- 64-byte signatures
- Deterministic (same message = same signature with same key)
- Fast verification (~20,000 sigs/sec per core)

**Implementation**: `ed25519-dalek` crate.

**Usage**:
```rust
use ed25519_dalek::{Keypair, Signature, Signer, Verifier};

// Key generation
let mut csprng = OsRng;
let keypair = Keypair::generate(&mut csprng);

// Signing
let message = b"meshara message";
let signature: Signature = keypair.sign(message);

// Verification
assert!(keypair.public.verify(message, &signature).is_ok());
```

**In Meshara**:
- Every node has one Ed25519 identity keypair
- All messages are signed before sending
- All received messages verified before processing
- Public key serves as node identity
- Signature verification is mandatory (cannot be disabled in production)

### X25519 Key Exchange

**Purpose**: Derive shared secrets for encryption.

**Properties**:
- Elliptic curve Diffie-Hellman
- 32-byte keys
- Provides forward secrecy
- Constant-time implementation (resistant to timing attacks)

**Implementation**: `x25519-dalek` crate.

**Usage**:
```rust
use x25519_dalek::{EphemeralSecret, PublicKey};

// Alice generates ephemeral key
let alice_secret = EphemeralSecret::random_from_rng(&mut OsRng);
let alice_public = PublicKey::from(&alice_secret);

// Bob's static public key (known in advance)
let bob_public: PublicKey = /* recipient's public key */;

// Alice computes shared secret
let shared_secret = alice_secret.diffie_hellman(&bob_public);
```

**In Meshara**:
- Each node has one X25519 static keypair for encryption
- Each private message uses ephemeral X25519 key for forward secrecy
- Ephemeral public key included in message
- Recipient combines their static key with sender's ephemeral key
- Shared secret used to derive encryption key

### ChaCha20-Poly1305 AEAD

**Purpose**: Authenticated encryption of message content.

**Properties**:
- Stream cipher (ChaCha20) + authenticator (Poly1305)
- Authenticated Encryption with Associated Data (AEAD)
- 256-bit keys, 96-bit nonces
- Fast (~2 GB/sec per core)
- Constant-time (no timing side channels)

**Implementation**: `chacha20poly1305` crate.

**Usage**:
```rust
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};

// Key derivation from shared secret
let key = /* derived from X25519 shared secret */;
let cipher = ChaCha20Poly1305::new(&key);

// Encrypt
let nonce = Nonce::from_slice(b"unique nonce"); // 96 bits
let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
    .expect("encryption failure");

// Decrypt
let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
    .expect("decryption failure");
```

**In Meshara**:
- All private message content encrypted with ChaCha20-Poly1305
- Key derived from X25519 shared secret using HKDF
- Random nonce generated for each message
- Nonce included in message (not secret)
- Poly1305 tag prevents tampering
- Decryption failure = authentication failure

### Blake3 Hashing

**Purpose**: Message IDs, checksums, key fingerprints.

**Properties**:
- Cryptographic hash function
- 256-bit output
- Extremely fast (~10 GB/sec per core)
- Parallel tree structure
- Supports keyed hashing and key derivation

**Implementation**: `blake3` crate.

**Usage**:
```rust
use blake3::Hasher;

// Simple hashing
let hash = blake3::hash(b"meshara");
let hex_hash = hash.to_hex();

// Incremental hashing
let mut hasher = Hasher::new();
hasher.update(b"part1");
hasher.update(b"part2");
let result = hasher.finalize();

// Keyed hashing (MAC)
let key = b"meshara authentication key 32b!";
let mac = blake3::keyed_hash(key, b"message");
```

**In Meshara**:
- Message IDs: Blake3(serialized message)
- Update checksums: Blake3(package binary)
- Key fingerprints: Blake3(public key) for human-readable IDs
- Deduplication: Message ID used in Bloom filter

### Argon2 Key Derivation

**Purpose**: Derive encryption keys from passphrases.

**Properties**:
- Memory-hard function (resistant to GPUs/ASICs)
- Configurable time/memory parameters
- Winner of Password Hashing Competition
- Protects against brute-force attacks

**Implementation**: `argon2` crate.

**Usage**:
```rust
use argon2::{Argon2, password_hash::{PasswordHasher, SaltString}};

let password = b"user passphrase";
let salt = SaltString::generate(&mut OsRng);

// Derive key
let argon2 = Argon2::default();
let password_hash = argon2.hash_password(password, &salt)
    .expect("hashing failure");

// Store: password_hash.to_string() contains salt + hash
```

**In Meshara**:
- User passphrases → encryption keys for keystore
- Protects private keys at rest
- Salt stored with encrypted key
- Default: 64 MiB memory, 3 iterations
- Key export also uses Argon2

## Key Management

### Identity Keys

Each node has two keypairs:

**Signing Keypair (Ed25519)**:
- Long-term identity
- Public key is the node's identity
- Signs all outgoing messages
- Never changes (unless identity reset)

**Encryption Keypair (X25519)**:
- Long-term encryption identity
- Derived from same seed as signing key
- Used for recipient in key exchange
- Never changes (unless identity reset)

**Key Generation**:
```rust
use rand::rngs::OsRng;

pub struct Identity {
    signing_key: ed25519_dalek::Keypair,
    encryption_key: x25519_dalek::StaticSecret,
}

impl Identity {
    pub fn generate() -> Self {
        let mut csprng = OsRng;

        // Generate signing key
        let signing_key = ed25519_dalek::Keypair::generate(&mut csprng);

        // Generate encryption key (separate, not derived)
        let encryption_key = x25519_dalek::StaticSecret::random_from_rng(&mut csprng);

        Self { signing_key, encryption_key }
    }

    pub fn public_signing_key(&self) -> &ed25519_dalek::PublicKey {
        &self.signing_key.public
    }

    pub fn public_encryption_key(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(&self.encryption_key)
    }
}
```

### Key Storage

Private keys encrypted at rest using passphrase-derived key.

**Storage Format**:
```rust
pub struct EncryptedKeystore {
    // Argon2 parameters
    salt: [u8; 32],
    memory_cost: u32,
    time_cost: u32,

    // Encrypted keys
    encrypted_signing_key: Vec<u8>,  // 64 bytes encrypted
    encrypted_encryption_key: Vec<u8>,  // 32 bytes encrypted

    // Nonces for ChaCha20-Poly1305
    signing_key_nonce: [u8; 12],
    encryption_key_nonce: [u8; 12],
}

impl EncryptedKeystore {
    pub fn save(&self, path: &Path, passphrase: &str) -> Result<(), Error> {
        // Derive key from passphrase
        let derived_key = argon2::derive_key(
            passphrase.as_bytes(),
            &self.salt,
            self.memory_cost,
            self.time_cost,
        )?;

        // Encrypt signing key
        let cipher = ChaCha20Poly1305::new(&derived_key);
        let encrypted_signing = cipher.encrypt(
            &self.signing_key_nonce.into(),
            self.signing_key.as_bytes()
        )?;

        // Similar for encryption key...

        // Write to disk
        std::fs::write(path, &serialize(&self))?;

        Ok(())
    }

    pub fn load(path: &Path, passphrase: &str) -> Result<Identity, Error> {
        // Read from disk
        let data = std::fs::read(path)?;
        let keystore: EncryptedKeystore = deserialize(&data)?;

        // Derive key from passphrase
        let derived_key = argon2::derive_key(
            passphrase.as_bytes(),
            &keystore.salt,
            keystore.memory_cost,
            keystore.time_cost,
        )?;

        // Decrypt keys
        let cipher = ChaCha20Poly1305::new(&derived_key);
        let signing_key_bytes = cipher.decrypt(
            &keystore.signing_key_nonce.into(),
            keystore.encrypted_signing_key.as_ref()
        )?;

        // Similar for encryption key...

        Ok(Identity { signing_key, encryption_key })
    }
}
```

**Security**:
- Keys never written to disk in plaintext
- Passphrase never stored
- Argon2 parameters tuned for ~100ms derivation time
- Salt prevents rainbow tables
- Each key has separate nonce

### Key Export/Import

For moving identity between devices.

**Export Format**:
```rust
pub struct IdentityBundle {
    version: u32,
    salt: [u8; 32],
    encrypted_data: Vec<u8>,  // Contains both keys + metadata
    nonce: [u8; 12],
}

impl Identity {
    pub fn export(&self, passphrase: &str) -> Result<Vec<u8>, Error> {
        // Serialize identity
        let serialized = serialize(&IdentityData {
            signing_key: self.signing_key.to_bytes(),
            encryption_key: self.encryption_key.to_bytes(),
            created_at: current_timestamp(),
        })?;

        // Encrypt with passphrase
        let salt = generate_salt();
        let key = argon2::derive_key(passphrase.as_bytes(), &salt,
                                     MEMORY_COST, TIME_COST)?;

        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = generate_nonce();
        let encrypted = cipher.encrypt(&nonce.into(), serialized.as_ref())?;

        // Create bundle
        let bundle = IdentityBundle {
            version: 1,
            salt,
            encrypted_data: encrypted,
            nonce,
        };

        Ok(serialize(&bundle)?)
    }

    pub fn import(bundle_bytes: &[u8], passphrase: &str) -> Result<Self, Error> {
        let bundle: IdentityBundle = deserialize(bundle_bytes)?;

        // Derive key
        let key = argon2::derive_key(passphrase.as_bytes(), &bundle.salt,
                                     MEMORY_COST, TIME_COST)?;

        // Decrypt
        let cipher = ChaCha20Poly1305::new(&key);
        let decrypted = cipher.decrypt(&bundle.nonce.into(),
                                       bundle.encrypted_data.as_ref())?;

        // Deserialize identity
        let data: IdentityData = deserialize(&decrypted)?;

        Ok(Self {
            signing_key: ed25519_dalek::Keypair::from_bytes(&data.signing_key)?,
            encryption_key: x25519_dalek::StaticSecret::from(data.encryption_key),
        })
    }
}
```

## Message Encryption Flow

### Sending Encrypted Message

**Complete flow for private message**:

```rust
pub async fn send_private_message(
    &self,
    recipient_public_key: &PublicKey,
    content: &[u8],
) -> Result<MessageId, Error> {
    // 1. Generate ephemeral key for forward secrecy
    let ephemeral_secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut OsRng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    // 2. Perform key exchange
    let recipient_x25519_key = recipient_public_key.encryption_key();
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519_key);

    // 3. Derive encryption key using HKDF
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut encryption_key = [0u8; 32];
    hkdf.expand(b"meshara-message-encryption", &mut encryption_key)?;

    // 4. Generate random nonce
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // 5. Encrypt content
    let cipher = ChaCha20Poly1305::new(&encryption_key.into());
    let ciphertext = cipher.encrypt(&nonce.into(), content)?;

    // 6. Create PrivateMessagePayload protobuf
    let payload = PrivateMessagePayload {
        content: ciphertext,
        ephemeral_public_key: ephemeral_public.as_bytes().to_vec(),
        nonce: nonce.to_vec(),
        return_path: self.create_return_path()?,
    };

    // 7. Serialize payload
    let payload_bytes = payload.encode_to_vec();

    // 8. Sign the encrypted payload
    let signature = self.identity.signing_key.sign(&payload_bytes);

    // 9. Create BaseMessage
    let message_id = blake3::hash(&payload_bytes);
    let base_message = BaseMessage {
        version: PROTOCOL_VERSION,
        message_id: message_id.as_bytes().to_vec(),
        message_type: MessageType::PrivateMessage as i32,
        timestamp: current_timestamp(),
        sender_public_key: self.identity.public_signing_key().as_bytes().to_vec(),
        payload: payload_bytes,
        signature: signature.to_bytes().to_vec(),
        routing_info: Some(self.create_routing_info(recipient_public_key)?),
    };

    // 10. Serialize and send
    let message_bytes = base_message.encode_to_vec();
    self.router.route_message(recipient_public_key, message_bytes).await?;

    Ok(MessageId::from(message_id))
}
```

### Receiving Encrypted Message

**Complete verification and decryption flow**:

```rust
pub async fn process_received_message(
    &self,
    message_bytes: &[u8],
) -> Result<MessageEvent, Error> {
    // 1. Deserialize BaseMessage
    let base_msg = BaseMessage::decode(message_bytes)
        .map_err(|e| Error::Protocol(ProtocolError::InvalidMessage))?;

    // 2. Verify signature (MANDATORY)
    let sender_public_key = ed25519_dalek::PublicKey::from_bytes(
        &base_msg.sender_public_key
    )?;

    let signature = ed25519_dalek::Signature::from_bytes(&base_msg.signature)?;

    sender_public_key.verify(&base_msg.payload, &signature)
        .map_err(|_| Error::Crypto(CryptoError::InvalidSignature))?;

    // 3. Check message type
    if base_msg.message_type != MessageType::PrivateMessage as i32 {
        return Err(Error::Protocol(ProtocolError::UnexpectedMessageType));
    }

    // 4. Deserialize PrivateMessagePayload
    let payload = PrivateMessagePayload::decode(base_msg.payload.as_ref())?;

    // 5. Extract ephemeral public key
    let ephemeral_public = x25519_dalek::PublicKey::from(
        <[u8; 32]>::try_from(payload.ephemeral_public_key.as_slice())?
    );

    // 6. Perform key exchange with our static key
    let shared_secret = self.identity.encryption_key.diffie_hellman(&ephemeral_public);

    // 7. Derive same encryption key
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut encryption_key = [0u8; 32];
    hkdf.expand(b"meshara-message-encryption", &mut encryption_key)?;

    // 8. Decrypt content
    let cipher = ChaCha20Poly1305::new(&encryption_key.into());
    let nonce = <[u8; 12]>::try_from(payload.nonce.as_slice())?;
    let plaintext = cipher.decrypt(&nonce.into(), payload.content.as_ref())
        .map_err(|_| Error::Crypto(CryptoError::DecryptionFailed))?;

    // 9. Create event
    Ok(MessageEvent {
        message_id: MessageId::from_bytes(&base_msg.message_id),
        sender: PublicKey::from(sender_public_key),
        content: plaintext,
        timestamp: base_msg.timestamp,
        verified: true,  // Signature verified in step 2
        message_type: MessageType::PrivateMessage,
    })
}
```

## Security Properties

### Forward Secrecy

Ephemeral keys ensure past messages can't be decrypted even if long-term keys compromised:

- Each message uses unique ephemeral X25519 key
- Ephemeral private key discarded after encryption
- Compromise of static key doesn't reveal past messages
- Only current and future messages at risk

### Authentication

Every message authenticated:

- Ed25519 signature on all messages
- Signature verification mandatory before processing
- Prevents message forgery
- Proves sender identity

### Integrity

Tampering detected through:

- AEAD encryption (Poly1305 tag)
- Ed25519 signatures
- Blake3 checksums for updates
- Any modification causes verification failure

### Confidentiality

Private message content protected:

- End-to-end encryption
- Only sender and recipient can decrypt
- Network observers see only ciphertext
- TLS provides additional transport encryption

## Cryptographic Guarantees

**Provided**:
- IND-CCA2 security (chosen-ciphertext attack resistance)
- EUF-CMA security (existential unforgeability under chosen-message attack)
- Forward secrecy
- Authenticity and integrity
- Confidentiality against passive and active attackers

**Not Provided**:
- Deniability (signatures prove sender identity)
- Traffic analysis resistance (without onion routing)
- Metadata privacy (who talks to whom visible to network)
- Post-quantum security (current algorithms vulnerable to quantum computers)

## Key Rotation

Currently not implemented. Future considerations:

- Periodic rotation of encryption keys
- Migration to post-quantum algorithms
- Backward compatibility during transition
- Key compromise recovery procedures
