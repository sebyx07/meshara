# Message Flow

This document traces the complete lifecycle of messages through the Meshara system, from application call to delivery.

## Private Message Flow

### Sending Private Message

**Complete end-to-end flow from API call to network transmission**.

```rust
// Application code
let message_id = node.send_private_message(recipient_public_key, b"Hello").await?;
```

**Step-by-step execution**:

#### 1. API Layer Entry Point

```rust
// src/api/node.rs
impl Node {
    pub async fn send_private_message(
        &self,
        recipient: &PublicKey,
        content: &[u8],
    ) -> Result<MessageId, Error> {
        // Validate inputs
        if content.len() > MAX_MESSAGE_SIZE {
            return Err(Error::MessageTooLarge);
        }

        // Delegate to message handler
        self.message_handler.send_private(recipient, content).await
    }
}
```

#### 2. Message Handler

```rust
// src/api/messaging.rs
impl MessageHandler {
    async fn send_private(
        &self,
        recipient: &PublicKey,
        content: &[u8],
    ) -> Result<MessageId, Error> {
        // Create message payload
        let payload = self.crypto.encrypt_for_recipient(recipient, content).await?;

        // Wrap in protocol message
        let base_message = self.protocol.create_private_message(
            &self.identity,
            recipient,
            payload,
        )?;

        // Sign message
        let signed_message = self.crypto.sign_message(
            &self.identity.signing_key,
            &base_message,
        )?;

        // Route message
        let message_id = signed_message.message_id.clone();
        self.router.route_message(recipient, signed_message).await?;

        Ok(message_id.into())
    }
}
```

#### 3. Encryption (Crypto Layer)

```rust
// src/crypto/encryption.rs
impl CryptoHandler {
    async fn encrypt_for_recipient(
        &self,
        recipient: &PublicKey,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, CryptoError> {
        // Generate ephemeral key for forward secrecy
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let ephemeral_public = x25519::PublicKey::from(&ephemeral_secret);

        // Perform X25519 key exchange
        let recipient_x25519 = recipient.encryption_key();
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519);

        // Derive encryption key using HKDF-SHA256
        let encryption_key = self.derive_encryption_key(&shared_secret)?;

        // Generate random nonce
        let nonce = self.generate_nonce();

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(&encryption_key);
        let ciphertext = cipher.encrypt(&nonce.into(), plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Create payload
        Ok(EncryptedPayload {
            ephemeral_public_key: ephemeral_public.to_bytes(),
            nonce,
            ciphertext,
        })
    }

    fn derive_encryption_key(
        &self,
        shared_secret: &SharedSecret,
    ) -> Result<[u8; 32], CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(b"meshara-message-encryption-v1", &mut key)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        Ok(key)
    }
}
```

#### 4. Protocol Serialization

```rust
// src/protocol/messages.rs
impl ProtocolHandler {
    fn create_private_message(
        &self,
        identity: &Identity,
        recipient: &PublicKey,
        encrypted_payload: EncryptedPayload,
    ) -> Result<BaseMessage, ProtocolError> {
        // Create PrivateMessagePayload protobuf
        let payload_proto = PrivateMessagePayload {
            content: encrypted_payload.ciphertext,
            ephemeral_public_key: encrypted_payload.ephemeral_public_key.to_vec(),
            nonce: encrypted_payload.nonce.to_vec(),
            return_path: self.create_return_path()?,
        };

        // Serialize payload
        let payload_bytes = payload_proto.encode_to_vec();

        // Compute message ID
        let message_id = blake3::hash(&payload_bytes);

        // Create BaseMessage
        let base_message = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: message_id.as_bytes().to_vec(),
            message_type: MessageType::PrivateMessage as i32,
            timestamp: current_timestamp_millis(),
            sender_public_key: identity.public_signing_key().to_bytes().to_vec(),
            payload: payload_bytes,
            signature: vec![],  // Filled in next step
            routing_info: Some(RoutingInfo {
                hop_count: 0,
                max_hops: 10,
                route_type: RouteType::Direct as i32,
                next_hop: recipient.to_bytes().to_vec(),
                onion_layers: vec![],
            }),
        };

        Ok(base_message)
    }
}
```

#### 5. Signing (Crypto Layer)

```rust
// src/crypto/signing.rs
impl CryptoHandler {
    fn sign_message(
        &self,
        signing_key: &ed25519::Keypair,
        message: &BaseMessage,
    ) -> Result<BaseMessage, CryptoError> {
        // Serialize message without signature
        let mut unsigned = message.clone();
        unsigned.signature = vec![];

        let message_bytes = unsigned.encode_to_vec();

        // Sign with Ed25519
        let signature = signing_key.sign(&message_bytes);

        // Attach signature
        let mut signed = message.clone();
        signed.signature = signature.to_bytes().to_vec();

        Ok(signed)
    }
}
```

#### 6. Routing Decision

```rust
// src/routing/mod.rs
impl Router {
    async fn route_message(
        &self,
        recipient: &PublicKey,
        message: BaseMessage,
    ) -> Result<(), RoutingError> {
        // Serialize message
        let message_bytes = message.encode_to_vec();

        // Determine routing strategy
        match self.config.privacy_level {
            PrivacyLevel::Standard => {
                // Try direct connection first
                if let Ok(()) = self.try_direct_route(recipient, &message_bytes).await {
                    return Ok(());
                }

                // Fall back to bridge routing
                self.route_via_bridges(recipient, message_bytes).await
            }

            PrivacyLevel::Enhanced | PrivacyLevel::Maximum => {
                #[cfg(feature = "onion-routing")]
                {
                    self.route_via_onion(recipient, message_bytes).await
                }

                #[cfg(not(feature = "onion-routing"))]
                {
                    self.route_via_bridges(recipient, message_bytes).await
                }
            }
        }
    }

    async fn try_direct_route(
        &self,
        recipient: &PublicKey,
        message_bytes: &[u8],
    ) -> Result<(), RoutingError> {
        // Check connection pool
        let conn = self.connection_pool.get(recipient).await
            .ok_or(RoutingError::NoConnection)?;

        // Send directly
        conn.send(message_bytes).await?;

        Ok(())
    }
}
```

#### 7. Network Transmission

```rust
// src/network/connection.rs
impl Connection {
    async fn send(&self, data: &[u8]) -> Result<(), NetworkError> {
        // Pad message for traffic analysis resistance
        let padded = self.pad_message(data);

        // Frame message (length prefix)
        let mut framed = Vec::with_capacity(padded.len() + 4);
        framed.extend_from_slice(&(padded.len() as u32).to_be_bytes());
        framed.extend_from_slice(&padded);

        // Send over TLS connection
        let mut stream = self.tls_stream.lock().await;
        stream.write_all(&framed).await?;
        stream.flush().await?;

        // Update metrics
        self.stats.bytes_sent.fetch_add(framed.len() as u64, Ordering::Relaxed);
        self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }
}
```

**Timeline Summary**:
1. API call: 0ms
2. Encryption: 0.1ms
3. Serialization: 0.05ms
4. Signing: 0.05ms
5. Routing decision: 0.01ms
6. Network send: 0.5-50ms (depends on network)
**Total**: ~1-50ms

### Receiving Private Message

**Complete flow from network reception to application callback**.

#### 1. Network Reception

```rust
// src/network/connection.rs
impl Connection {
    async fn receive(&self) -> Result<Vec<u8>, NetworkError> {
        // Read length prefix (4 bytes)
        let mut len_buf = [0u8; 4];
        let mut stream = self.tls_stream.lock().await;
        stream.read_exact(&mut len_buf).await?;

        let len = u32::from_be_bytes(len_buf) as usize;

        // Validate size
        if len > MAX_MESSAGE_SIZE {
            return Err(NetworkError::MessageTooLarge);
        }

        // Read message data
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        // Remove padding
        let message = self.remove_padding(&buf)?;

        // Update metrics
        self.stats.bytes_received.fetch_add(len as u64, Ordering::Relaxed);
        self.stats.messages_received.fetch_add(1, Ordering::Relaxed);

        Ok(message)
    }
}
```

#### 2. Connection Manager Dispatch

```rust
// src/network/manager.rs
impl NetworkManager {
    async fn handle_incoming_message(
        &self,
        conn: &Connection,
        message_bytes: Vec<u8>,
    ) -> Result<(), Error> {
        // Deserialize BaseMessage
        let base_message = BaseMessage::decode(message_bytes.as_ref())
            .map_err(|_| Error::Protocol(ProtocolError::DeserializationFailed))?;

        // Dispatch based on message type
        match MessageType::from_i32(base_message.message_type) {
            Some(MessageType::PrivateMessage) => {
                self.message_processor.process_private_message(base_message).await
            }
            Some(MessageType::Broadcast) => {
                self.message_processor.process_broadcast(base_message).await
            }
            Some(MessageType::UpdatePackage) => {
                self.update_processor.process_update(base_message).await
            }
            Some(MessageType::Query) => {
                self.query_processor.process_query(base_message).await
            }
            _ => Err(Error::Protocol(ProtocolError::UnknownMessageType)),
        }
    }
}
```

#### 3. Signature Verification (MANDATORY)

```rust
// src/crypto/signing.rs
impl MessageProcessor {
    async fn process_private_message(
        &self,
        base_message: BaseMessage,
    ) -> Result<(), Error> {
        // Extract sender's public key
        let sender_public_key = ed25519::PublicKey::from_bytes(
            &base_message.sender_public_key
        ).map_err(|_| Error::Crypto(CryptoError::InvalidPublicKey))?;

        // Extract signature
        let signature = ed25519::Signature::from_bytes(&base_message.signature)
            .map_err(|_| Error::Crypto(CryptoError::InvalidSignature))?;

        // Reconstruct unsigned message
        let mut unsigned = base_message.clone();
        unsigned.signature = vec![];
        let unsigned_bytes = unsigned.encode_to_vec();

        // Verify signature
        sender_public_key.verify(&unsigned_bytes, &signature)
            .map_err(|_| Error::Crypto(CryptoError::SignatureVerificationFailed))?;

        // Signature valid - proceed with processing
        self.process_verified_message(base_message, sender_public_key).await
    }
}
```

#### 4. Deduplication Check

```rust
impl MessageProcessor {
    async fn process_verified_message(
        &self,
        message: BaseMessage,
        sender: ed25519::PublicKey,
    ) -> Result<(), Error> {
        // Compute message ID
        let message_id = MessageId::from_bytes(&message.message_id);

        // Check if already processed
        let mut dedup = self.deduplication.lock().await;
        if dedup.contains(&message_id) {
            // Already processed - ignore
            return Ok(());
        }

        // Mark as seen
        dedup.insert(&message_id);
        drop(dedup);

        // Continue processing
        self.decrypt_and_deliver(message, sender).await
    }
}
```

#### 5. Decryption

```rust
// src/crypto/encryption.rs
impl MessageProcessor {
    async fn decrypt_and_deliver(
        &self,
        message: BaseMessage,
        sender: ed25519::PublicKey,
    ) -> Result<(), Error> {
        // Deserialize PrivateMessagePayload
        let payload = PrivateMessagePayload::decode(message.payload.as_ref())
            .map_err(|_| Error::Protocol(ProtocolError::InvalidPayload))?;

        // Extract ephemeral public key
        let ephemeral_public = x25519::PublicKey::from(
            <[u8; 32]>::try_from(payload.ephemeral_public_key.as_slice())
                .map_err(|_| Error::Crypto(CryptoError::InvalidKey))?
        );

        // Perform key exchange with our static encryption key
        let shared_secret = self.identity.encryption_key.diffie_hellman(&ephemeral_public);

        // Derive same encryption key
        let encryption_key = self.crypto.derive_encryption_key(&shared_secret)?;

        // Extract nonce
        let nonce = <[u8; 12]>::try_from(payload.nonce.as_slice())
            .map_err(|_| Error::Crypto(CryptoError::InvalidNonce))?;

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(&encryption_key);
        let plaintext = cipher.decrypt(&nonce.into(), payload.content.as_ref())
            .map_err(|_| Error::Crypto(CryptoError::DecryptionFailed))?;

        // Create event
        let event = MessageEvent {
            message_id: MessageId::from_bytes(&message.message_id),
            sender: PublicKey::from_signing_key(sender),
            content: plaintext,
            timestamp: message.timestamp,
            verified: true,
            message_type: MessageType::PrivateMessage,
        };

        // Deliver to application
        self.event_dispatcher.dispatch(event).await
    }
}
```

#### 6. Event Delivery

```rust
// src/api/events.rs
impl EventDispatcher {
    async fn dispatch(&self, event: MessageEvent) -> Result<(), Error> {
        // Get subscribers for this event type
        let subscribers = self.subscribers.read().await;
        let callbacks = subscribers.get(&EventType::MessageReceived)
            .ok_or(Error::NoSubscribers)?;

        // Deliver to all subscribers concurrently
        let mut tasks = vec![];
        for callback in callbacks {
            let event = event.clone();
            let callback = callback.clone();

            tasks.push(tokio::spawn(async move {
                callback(event).await
            }));
        }

        // Wait for all callbacks to complete
        let results = futures::future::join_all(tasks).await;

        // Check for errors
        for result in results {
            if let Err(e) = result {
                tracing::warn!("Event callback failed: {:?}", e);
            }
        }

        Ok(())
    }
}
```

#### 7. Application Callback

```rust
// Application code
node.on_message_received(|event| async move {
    println!("Message from {}: {:?}",
             event.sender.to_hex(),
             String::from_utf8_lossy(&event.content));

    // Verify signature was checked
    assert!(event.verified);
});
```

**Timeline Summary**:
1. Network receive: 0.5-50ms
2. Deserialization: 0.05ms
3. Signature verification: 0.05ms
4. Deduplication check: 0.01ms
5. Decryption: 0.1ms
6. Event dispatch: 0.1ms
7. Application callback: varies
**Total**: ~1-50ms

## Broadcast Message Flow

### Sending Broadcast

```rust
// Application code
let message_id = node.broadcast_message(b"Public announcement").await?;
```

**Simplified flow** (no encryption):

1. **API Layer**: Create BroadcastPayload (no encryption)
2. **Signing**: Sign payload with Ed25519
3. **Protocol**: Wrap in BaseMessage
4. **Gossip**: Send to all connected peers
5. **Return**: Message ID immediately

### Receiving Broadcast

1. **Network**: Receive from peer
2. **Verification**: Verify signature
3. **Deduplication**: Check Bloom filter
4. **Rebroadcast**: Forward to other peers (if not seen)
5. **Deliver**: Trigger MessageReceived event

**Gossip Propagation**:
```rust
impl GossipProtocol {
    async fn handle_broadcast(
        &mut self,
        message: BaseMessage,
    ) -> Result<(), Error> {
        // Compute message ID
        let msg_id = MessageId::from_bytes(&message.message_id);

        // Check if seen
        if self.seen_messages.contains(&msg_id) {
            return Ok(());  // Already processed
        }

        // Mark as seen
        self.seen_messages.insert(&msg_id);

        // Verify signature
        self.verify_signature(&message)?;

        // Process locally
        self.deliver_locally(&message).await?;

        // Rebroadcast to peers (except sender)
        let peers = self.select_gossip_targets(message.sender_public_key);
        for peer in peers {
            let _ = self.send_to_peer(&peer, &message).await;
            // Best-effort - ignore errors
        }

        Ok(())
    }

    fn select_gossip_targets(&self, exclude: Vec<u8>) -> Vec<PublicKey> {
        let peers = self.connection_pool.list_peers();

        // Filter out sender
        let candidates: Vec<_> = peers.into_iter()
            .filter(|p| p.public_key.to_bytes() != exclude)
            .collect();

        // Select random subset (fanout)
        if candidates.len() <= self.fanout {
            candidates
        } else {
            candidates.into_iter()
                .choose_multiple(&mut rand::thread_rng(), self.fanout)
        }
    }
}
```

**Propagation Timeline**:
- 100 nodes, fanout=10
- Hop 1: 10 nodes (100ms)
- Hop 2: 90+ nodes (200ms)
- Hop 3: ~100 nodes (300ms)
**Total**: ~300ms for full propagation

## Update Package Flow

### Authority Publishes Update

```rust
// Authority node
authority_node.publish_update(
    "v2.0.0",
    update_binary,
    "New features: ..."
).await?;
```

1. **Create UpdatePackage** protobuf
2. **Compute checksum** (Blake3)
3. **Sign with authority key** (Ed25519)
4. **Broadcast via gossip** to all peers

### Client Receives Update

1. **Receive broadcast** message
2. **Verify signature** against trusted authority list
3. **Verify checksum** of package data
4. **Trigger UpdateAvailable** event
5. **Application decides** whether to apply

```rust
// Application code
node.on_update_available(|update_event| async move {
    if !update_event.verified {
        println!("Update signature invalid - ignoring");
        return;
    }

    println!("Update {} available: {}",
             update_event.version,
             update_event.changelog);

    // Verify checksum
    let computed = blake3::hash(&update_event.package_data);
    let expected = &update_event.checksum;

    if computed.as_bytes() != expected {
        println!("Checksum mismatch - corrupted update");
        return;
    }

    // Prompt user or auto-apply
    if auto_update_enabled {
        apply_update(&update_event.package_data).await;
    }
});
```

## Query/Response Flow

### Sending Query

```rust
let response = node.query_authority(
    authority_id,
    query_data,
    Duration::from_secs(30)
).await?;
```

1. **Encrypt query** for authority
2. **Create QueryMessage** with query ID
3. **Route to authority** (direct or via bridges)
4. **Wait for response** (with timeout)

### Authority Responds

1. **Receive QueryMessage**
2. **Verify signature**
3. **Decrypt query data**
4. **Process query** (application logic)
5. **Encrypt response**
6. **Send ResponseMessage** (using return_path)

```rust
// Authority node
node.on_query_received(|query_event| async move {
    // Process query
    let response_data = process_query(&query_event.query_data);

    // Send response
    node.respond_to_query(query_event.query_id, response_data).await
});
```

**Timeline**:
- Query encryption: 0.1ms
- Route to authority: 50-500ms
- Authority processing: varies
- Response route back: 50-500ms
- Response decryption: 0.1ms
**Total**: 100ms - 30 seconds (with timeout)

## Error Handling

**Network Errors**: Retry with exponential backoff

**Signature Failures**: Drop message, log potential attack

**Decryption Failures**: Drop message (wrong recipient or corrupted)

**Timeout**: Return error to application, don't retry automatically

**Unknown Message Type**: Log and ignore

## Performance Summary

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Send Private (local) | 1-50ms | 1000/sec |
| Send Private (internet) | 50-500ms | 100/sec |
| Broadcast (100 nodes) | 300ms | N/A |
| Signature Verify | 0.05ms | 20k/sec |
| Encrypt/Decrypt | 0.1ms | 10k/sec |
| DHT Lookup | 300-800ms | N/A |
| Onion Route (3 hops) | 500-1000ms | 100/sec |
