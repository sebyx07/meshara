//! Integration tests for Meshara
//!
//! These tests verify end-to-end functionality across multiple components.

mod common;

use common::*;
use meshara::crypto::*;
use meshara::protocol::*;
use meshara::storage::config::*;
use meshara::storage::keystore::*;

#[cfg(test)]
mod crypto_integration {
    use super::*;

    /// Test complete crypto workflow: generate identity, sign, verify, encrypt, decrypt
    #[test]
    fn test_complete_crypto_workflow() {
        // Create sender and recipient
        let sender = create_test_identity();
        let recipient = create_test_identity();

        let sender_pubkey = sender.public_key();
        let recipient_pubkey = recipient.public_key();

        // Create a message
        let message = b"Secret communication";

        // Sign the message
        let signature = sign_message(&sender, message);

        // Verify signature
        assert!(verify_signature(&sender_pubkey, message, &signature));

        // Encrypt the message
        let encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, message).unwrap();

        // Decrypt the message
        let decrypted = decrypt_message(&recipient, &encrypted).unwrap();

        // Verify decrypted matches original
        assert_eq!(decrypted, message);
    }

    /// Test signing and encryption together
    #[test]
    fn test_sign_then_encrypt() {
        let alice = create_test_identity_from_seed(1);
        let bob = create_test_identity_from_seed(2);

        let alice_pubkey = alice.public_key();
        let bob_pubkey = bob.public_key();

        let message = b"Important message";

        // Alice signs the message
        let signature = sign_message(&alice, message);

        // Serialize signature and message together
        let mut signed_message = Vec::new();
        signed_message.extend_from_slice(&signature.to_bytes());
        signed_message.extend_from_slice(message);

        // Alice encrypts the signed message for Bob
        let encrypted = encrypt_for_recipient(&alice, &bob_pubkey, &signed_message).unwrap();

        // Bob decrypts
        let decrypted = decrypt_message(&bob, &encrypted).unwrap();

        // Extract signature and message
        let received_signature =
            Signature::from_bytes(&decrypted[..64].try_into().unwrap()).unwrap();
        let received_message = &decrypted[64..];

        // Verify signature
        assert!(verify_signature(
            &alice_pubkey,
            received_message,
            &received_signature
        ));
        assert_eq!(received_message, message);
    }

    /// Test multi-party encryption
    #[test]
    fn test_multiparty_encryption() {
        let sender = create_test_identity_from_seed(0);
        let recipients = create_test_identities(5);

        let message = b"Broadcast message";

        // Encrypt for each recipient
        for recipient in &recipients {
            let recipient_pubkey = recipient.public_key();
            let encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, message).unwrap();
            let decrypted = decrypt_message(recipient, &encrypted).unwrap();
            assert_eq!(decrypted, message);
        }
    }

    /// Test hash consistency across crypto operations
    #[test]
    fn test_hash_consistency() {
        let identity = create_test_identity();
        let public_key = identity.public_key();

        // Hash the public key to get NodeId
        let node_id1 = hash_public_key(&public_key);
        let node_id2 = hash_public_key(&public_key);

        // Should be deterministic
        assert_eq!(node_id1, node_id2);

        // Hash a message
        let message = b"Test message";
        let message_id1 = hash_message(message);
        let message_id2 = hash_message(message);

        // Should be deterministic
        assert_eq!(message_id1, message_id2);
    }
}

#[cfg(test)]
mod protocol_integration {
    use super::*;

    /// Test creating, signing, serializing, and verifying a complete message
    #[test]
    fn test_complete_message_lifecycle() {
        let sender = create_test_identity();
        let sender_pubkey = sender.public_key();

        // Create message payload
        let payload_content = b"Hello, Meshara!";
        let private_payload = PrivateMessagePayload {
            content: payload_content.to_vec(),
            return_path: vec![],
            ephemeral_public_key: vec![5u8; 32],
            nonce: vec![6u8; 12],
        };

        // Serialize payload
        let payload_bytes = serialize_message(&private_payload).unwrap();

        // Create message ID
        let message_id = hash_message(&payload_bytes);

        // Create base message
        let base_message = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: message_id.as_bytes().to_vec(),
            message_type: MessageType::PrivateMessage as i32,
            timestamp: 1234567890,
            sender_public_key: sender_pubkey.to_bytes()[..32].to_vec(), // Just signing key
            payload: payload_bytes.clone(),
            signature: vec![0u8; 64], // Placeholder
            routing_info: None,
        };

        // Sign the message (in practice, this would sign serialized base message minus signature)
        let signature = sign_message(&sender, &payload_bytes);

        // Update message with real signature
        let mut signed_message = base_message;
        signed_message.signature = signature.to_bytes().to_vec();

        // Validate the message
        assert!(validate_base_message(&signed_message).is_ok());

        // Serialize complete message
        let message_bytes = serialize_message(&signed_message).unwrap();

        // Deserialize
        let deserialized: BaseMessage = deserialize_message(&message_bytes).unwrap();

        // Verify fields match
        assert_eq!(deserialized.version, signed_message.version);
        assert_eq!(deserialized.message_id, signed_message.message_id);
        assert_eq!(deserialized.payload, signed_message.payload);
    }

    /// Test serialization of all message types
    #[test]
    fn test_all_message_types_serialization() {
        // Private message
        let private_msg = PrivateMessagePayload {
            content: b"Private".to_vec(),
            return_path: vec![],
            ephemeral_public_key: vec![1u8; 32],
            nonce: vec![2u8; 12],
        };
        let bytes = serialize_message(&private_msg).unwrap();
        let _deserialized: PrivateMessagePayload = deserialize_message(&bytes).unwrap();

        // Broadcast
        let broadcast_msg = BroadcastPayload {
            content: b"Broadcast".to_vec(),
            content_type: "text/plain".to_string(),
            metadata: std::collections::HashMap::new(),
        };
        let bytes = serialize_message(&broadcast_msg).unwrap();
        let _deserialized: BroadcastPayload = deserialize_message(&bytes).unwrap();

        // Update package
        let update_msg = UpdatePackage {
            version: "1.0.0".to_string(),
            package_data: vec![10u8; 100],
            changelog: "Initial".to_string(),
            checksum: vec![11u8; 32],
            required_version: "0.9.0".to_string(),
            signatures: vec![vec![12u8; 64]],
            authority_public_keys: vec![vec![13u8; 32]],
        };
        let bytes = serialize_message(&update_msg).unwrap();
        let _deserialized: UpdatePackage = deserialize_message(&bytes).unwrap();

        // Query
        let query_msg = QueryMessage {
            query_id: vec![20u8; 32],
            query_type: "test".to_string(),
            query_data: vec![],
            response_required: true,
            timeout_ms: 5000,
        };
        let bytes = serialize_message(&query_msg).unwrap();
        let _deserialized: QueryMessage = deserialize_message(&bytes).unwrap();

        // Response
        let response_msg = ResponseMessage {
            query_id: vec![20u8; 32],
            response_data: vec![],
            response_code: ResponseCode::Success as i32,
        };
        let bytes = serialize_message(&response_msg).unwrap();
        let _deserialized: ResponseMessage = deserialize_message(&bytes).unwrap();
    }

    /// Test protocol version handling
    #[test]
    fn test_protocol_version_validation() {
        let valid_message = BaseMessage {
            version: PROTOCOL_VERSION,
            message_id: vec![0u8; 32],
            message_type: MessageType::PrivateMessage as i32,
            timestamp: 1234567890,
            sender_public_key: vec![1u8; 32],
            payload: vec![],
            signature: vec![3u8; 64],
            routing_info: None,
        };

        assert!(validate_base_message(&valid_message).is_ok());

        let mut invalid_message = valid_message;
        invalid_message.version = 999;

        assert!(validate_base_message(&invalid_message).is_err());
    }
}

#[cfg(test)]
mod storage_integration {
    use super::*;

    /// Test complete storage workflow: save identity, save config, load both
    #[test]
    fn test_complete_storage_workflow() {
        let temp_dir = create_temp_storage();
        let identity_path = temp_dir.path().join("identity.enc");
        let config_path = temp_dir.path().join("config.json");

        // Create and save identity
        let identity = create_test_identity();
        let original_fingerprint = identity.public_key().fingerprint();
        let passphrase = "test passphrase 12345";

        save_identity(&identity_path, &identity, passphrase).unwrap();

        // Create and save config
        let node_id = hash_public_key(&identity.public_key()).to_hex();
        let config = NodeConfig::new(node_id.clone())
            .with_port(8080)
            .with_max_peers(100);

        save_config(&config_path, &config).unwrap();

        // Load identity
        let loaded_identity = load_identity(&identity_path, passphrase).unwrap();
        assert_eq!(
            loaded_identity.public_key().fingerprint(),
            original_fingerprint
        );

        // Load config
        let loaded_config = load_config(&config_path).unwrap();
        assert_eq!(loaded_config.node_id, node_id);
        assert_eq!(loaded_config.listen_port, 8080);
        assert_eq!(loaded_config.max_peers, 100);
    }

    /// Test identity persistence across multiple save/load cycles
    #[test]
    fn test_identity_persistence() {
        let temp_dir = create_temp_storage();
        let identity_path = temp_dir.path().join("identity.enc");

        let identity = create_test_identity_from_seed(42);
        let expected_fingerprint = identity.public_key().fingerprint();
        let passphrase = "persistent passphrase";

        // Save and load 10 times
        for _ in 0..10 {
            save_identity(&identity_path, &identity, passphrase).unwrap();
            let loaded = load_identity(&identity_path, passphrase).unwrap();
            assert_eq!(loaded.public_key().fingerprint(), expected_fingerprint);
        }
    }

    /// Test config update workflow
    #[test]
    fn test_config_update_workflow() {
        let temp_dir = create_temp_storage();
        let config_path = temp_dir.path().join("config.json");

        // Save initial config
        let mut config = NodeConfig::new("node1".to_string()).with_port(8080);
        save_config(&config_path, &config).unwrap();

        // Load and modify
        let loaded = load_config(&config_path).unwrap();
        assert_eq!(loaded.listen_port, 8080);

        // Update and save
        config.listen_port = 9090;
        save_config(&config_path, &config).unwrap();

        // Verify update
        let updated = load_config(&config_path).unwrap();
        assert_eq!(updated.listen_port, 9090);
    }
}

#[cfg(test)]
mod cross_module_integration {
    use super::*;

    /// Test complete end-to-end: create identity, save, load, sign, verify
    #[test]
    fn test_identity_storage_and_crypto() {
        let temp_dir = create_temp_storage();
        let identity_path = temp_dir.path().join("identity.enc");
        let passphrase = "test passphrase";

        // Create and save identity
        let original_identity = create_test_identity();
        save_identity(&identity_path, &original_identity, passphrase).unwrap();

        // Load identity
        let loaded_identity = load_identity(&identity_path, passphrase).unwrap();

        // Sign with original
        let message = b"Test message";
        let signature = sign_message(&original_identity, message);

        // Verify with loaded
        let loaded_pubkey = loaded_identity.public_key();
        assert!(verify_signature(&loaded_pubkey, message, &signature));

        // Sign with loaded
        let signature2 = sign_message(&loaded_identity, message);

        // Verify with original
        let original_pubkey = original_identity.public_key();
        assert!(verify_signature(&original_pubkey, message, &signature2));
    }

    /// Test encrypted message with protocol serialization
    #[test]
    fn test_encrypted_protocol_message() {
        let sender = create_test_identity_from_seed(1);
        let recipient = create_test_identity_from_seed(2);
        let recipient_pubkey = recipient.public_key();

        // Create payload
        let plaintext = b"Secret payload";

        // Encrypt
        let encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, plaintext).unwrap();

        // Create private message payload
        let payload = PrivateMessagePayload {
            content: encrypted.ciphertext.clone(),
            return_path: vec![],
            ephemeral_public_key: encrypted.ephemeral_public_key.to_vec(),
            nonce: encrypted.nonce.to_vec(),
        };

        // Serialize
        let payload_bytes = serialize_message(&payload).unwrap();

        // Deserialize
        let deserialized: PrivateMessagePayload = deserialize_message(&payload_bytes).unwrap();

        // Reconstruct encrypted message
        let reconstructed = EncryptedMessage {
            ephemeral_public_key: deserialized.ephemeral_public_key.try_into().unwrap(),
            nonce: deserialized.nonce.try_into().unwrap(),
            ciphertext: deserialized.content,
        };

        // Decrypt
        let decrypted = decrypt_message(&recipient, &reconstructed).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Test complete node setup from storage
    #[test]
    fn test_complete_node_setup_from_storage() {
        let temp_dir = create_temp_storage();
        let identity_path = temp_dir.path().join("identity.enc");
        let config_path = temp_dir.path().join("config.json");
        let passphrase = "node passphrase";

        // Create new node identity
        let identity = create_test_identity();
        let node_id = hash_public_key(&identity.public_key()).to_hex();

        // Save identity
        save_identity(&identity_path, &identity, passphrase).unwrap();

        // Create and save config
        let config = NodeConfig::new(node_id.clone())
            .with_port(8080)
            .with_network_profile(NetworkProfile::Standard)
            .with_privacy_level(PrivacyLevel::Enhanced);

        save_config(&config_path, &config).unwrap();

        // Simulate node restart: load everything
        let loaded_identity = load_identity(&identity_path, passphrase).unwrap();
        let loaded_config = load_config(&config_path).unwrap();

        // Verify node can operate
        assert_eq!(
            hash_public_key(&loaded_identity.public_key()).to_hex(),
            loaded_config.node_id
        );

        // Test crypto operations
        let message = b"Node is operational";
        let signature = sign_message(&loaded_identity, message);
        assert!(verify_signature(
            &loaded_identity.public_key(),
            message,
            &signature
        ));
    }
}

#[cfg(test)]
mod phase2_tests {
    //! Phase 2 integration tests will go here
    //! - Node API
    //! - In-memory message passing
    //! - Event system
}

#[cfg(test)]
mod phase3_tests {
    //! Phase 3 integration tests will go here
    //! - Network connections
    //! - TLS handshake
    //! - Message delivery over network
}

#[cfg(test)]
mod phase4_tests {
    //! Phase 4 integration tests will go here
    //! - Routing through mesh
    //! - Peer discovery
    //! - Multi-hop messages
}

#[cfg(test)]
mod phase5_tests {
    //! Phase 5 integration tests will go here
    //! - Authority nodes
    //! - Update distribution
    //! - Signature verification
}
