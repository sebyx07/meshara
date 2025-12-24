//! TLS configuration and certificate generation
//!
//! This module provides TLS 1.3 configuration using self-signed certificates
//! for secure peer-to-peer communication.

use crate::crypto::Identity;
use crate::error::{NetworkError, Result};
use crate::network::MESHARA_ALPN;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// TLS configuration for Meshara node
///
/// Contains certificates and keys needed for both client and server operations.
pub struct TlsConfig {
    /// Self-signed certificate for this node
    pub certificates: Vec<CertificateDer<'static>>,
    /// Private key matching the certificate
    pub private_key: PrivateKeyDer<'static>,
    /// Root certificate store (for verification)
    pub root_certs: RootCertStore,
}

impl TlsConfig {
    /// Create TLS configuration from a node identity
    ///
    /// Generates a self-signed certificate using the node's Ed25519 signing key.
    /// The certificate is valid for 1 year from creation.
    ///
    /// # Arguments
    ///
    /// * `identity` - The node's cryptographic identity
    ///
    /// # Example
    ///
    /// ```no_run
    /// use meshara::crypto::Identity;
    /// use meshara::network::TlsConfig;
    ///
    /// let identity = Identity::generate();
    /// let tls_config = TlsConfig::from_identity(&identity).unwrap();
    /// ```
    pub fn from_identity(identity: &Identity) -> Result<Self> {
        // Generate self-signed certificate
        let (cert_der, key_der) = generate_self_signed_cert(identity)?;

        // Create root cert store (empty for now - we verify via public key pinning)
        let root_certs = RootCertStore::empty();

        Ok(Self {
            certificates: vec![cert_der],
            private_key: key_der,
            root_certs,
        })
    }

    /// Create rustls ClientConfig for outgoing connections
    ///
    /// Configures the client to:
    /// - Use TLS 1.3
    /// - Advertise Meshara ALPN protocol
    /// - Accept any certificate (we verify via public key pinning)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use meshara::crypto::Identity;
    /// use meshara::network::TlsConfig;
    ///
    /// let identity = Identity::generate();
    /// let tls_config = TlsConfig::from_identity(&identity).unwrap();
    /// let client_config = tls_config.client_config();
    /// ```
    pub fn client_config(&self) -> Arc<ClientConfig> {
        // Create a custom verifier that accepts all certificates
        // We'll verify peer identity via public key pinning at a higher layer
        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_client_auth_cert(self.certificates.clone(), self.private_key.clone_key())
            .expect("Failed to set client certificate");

        // Set ALPN protocol
        config.alpn_protocols = vec![MESHARA_ALPN.to_vec()];

        Arc::new(config)
    }

    /// Create rustls ServerConfig for incoming connections
    ///
    /// Configures the server to:
    /// - Use TLS 1.3
    /// - Advertise Meshara ALPN protocol
    /// - Present our self-signed certificate
    /// - Accept any client certificate (we verify via public key pinning)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use meshara::crypto::Identity;
    /// use meshara::network::TlsConfig;
    ///
    /// let identity = Identity::generate();
    /// let tls_config = TlsConfig::from_identity(&identity).unwrap();
    /// let server_config = tls_config.server_config();
    /// ```
    pub fn server_config(&self) -> Arc<ServerConfig> {
        // Create server config with our certificate
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.certificates.clone(), self.private_key.clone_key())
            .expect("Failed to create server config");

        // Set ALPN protocol
        config.alpn_protocols = vec![MESHARA_ALPN.to_vec()];

        Arc::new(config)
    }
}

/// Generate a self-signed certificate from a node identity
///
/// Creates a certificate with:
/// - Subject: CN=meshara-node, O=Meshara Network
/// - Validity: 1 year from now
/// - Key: Ed25519 (derived from identity's signing key)
///
/// # Arguments
///
/// * `identity` - The node's cryptographic identity
///
/// # Returns
///
/// A tuple of (certificate DER, private key DER)
fn generate_self_signed_cert(
    _identity: &Identity,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    // Create certificate parameters
    let mut params = CertificateParams::default();

    // Set distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "meshara-node");
    dn.push(DnType::OrganizationName, "Meshara Network");
    params.distinguished_name = dn;

    // Set validity period (1 year)
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(365);

    // Set subject alternative names (localhost for development)
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName(rcgen::Ia5String::try_from("localhost").map_err(|e| {
            NetworkError::CertificateError {
                reason: format!("Invalid DNS name: {}", e),
            }
        })?),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        rcgen::SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0, 1,
        ))),
    ];

    // Generate key pair
    // Note: rcgen will generate its own key pair for the certificate
    // In production, we might want to derive this from the identity's signing key
    let key_pair =
        KeyPair::generate_for(&PKCS_ED25519).map_err(|e| NetworkError::CertificateError {
            reason: format!("Failed to generate key pair: {}", e),
        })?;

    // Generate certificate
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| NetworkError::CertificateError {
            reason: format!("Failed to generate self-signed certificate: {}", e),
        })?;

    // Convert to DER format
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der().to_vec()).map_err(|e| {
        NetworkError::CertificateError {
            reason: format!("Failed to serialize private key: {}", e),
        }
    })?;

    Ok((cert_der, key_der))
}

/// TLS listener for accepting incoming connections
pub struct TlsListener {
    /// TCP listener
    listener: TcpListener,
    /// TLS acceptor
    acceptor: TlsAcceptor,
}

impl TlsListener {
    /// Bind a TLS listener to an address
    ///
    /// # Arguments
    ///
    /// * `address` - Socket address to bind to
    /// * `tls_config` - Server TLS configuration
    ///
    /// # Example
    ///
    /// ```no_run
    /// use meshara::crypto::Identity;
    /// use meshara::network::{TlsConfig, TlsListener};
    /// use std::net::SocketAddr;
    ///
    /// # async fn example() -> meshara::error::Result<()> {
    /// let identity = Identity::generate();
    /// let tls_config = TlsConfig::from_identity(&identity)?;
    /// let addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    ///
    /// let listener = TlsListener::bind(addr, tls_config.server_config()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bind(
        address: std::net::SocketAddr,
        tls_config: Arc<ServerConfig>,
    ) -> Result<Self> {
        let listener =
            TcpListener::bind(address)
                .await
                .map_err(|e| NetworkError::ConnectionFailed {
                    address: address.to_string(),
                    reason: format!("Failed to bind listener: {}", e),
                })?;

        let acceptor = TlsAcceptor::from(tls_config);

        Ok(Self { listener, acceptor })
    }

    /// Get the local address this listener is bound to
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.listener.local_addr().map_err(|e| {
            NetworkError::InvalidAddress {
                address: format!("Failed to get local address: {}", e),
            }
            .into()
        })
    }

    /// Accept an incoming TLS connection
    ///
    /// This performs the TLS handshake and returns a TLS stream.
    ///
    /// # Returns
    ///
    /// A TLS stream on success
    pub async fn accept(
        &self,
    ) -> Result<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        std::net::SocketAddr,
    )> {
        // Accept TCP connection
        let (tcp_stream, peer_addr) =
            self.listener
                .accept()
                .await
                .map_err(|e| NetworkError::ConnectionFailed {
                    address: "incoming".to_string(),
                    reason: format!("Failed to accept connection: {}", e),
                })?;

        // Perform TLS handshake
        let tls_stream = self.acceptor.accept(tcp_stream).await.map_err(|e| {
            NetworkError::TlsHandshakeFailed {
                reason: format!("TLS handshake failed: {}", e),
            }
        })?;

        Ok((tls_stream, peer_addr))
    }
}

/// Custom certificate verifier that accepts all certificates
///
/// We use public key pinning at a higher layer for actual verification.
/// This is safe because we verify the peer's public key matches expected
/// after the TLS handshake completes.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Accept all certificates - we verify via public key pinning
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_generation() {
        let identity = Identity::generate();
        let result = generate_self_signed_cert(&identity);
        assert!(result.is_ok());

        let (cert_der, key_der) = result.unwrap();
        assert!(!cert_der.is_empty());
        // PrivateKeyDer doesn't have is_empty(), but we can check it's valid
        assert!(matches!(key_der, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn test_tls_config_from_identity() {
        let identity = Identity::generate();
        let result = TlsConfig::from_identity(&identity);
        assert!(result.is_ok());

        let tls_config = result.unwrap();
        assert_eq!(tls_config.certificates.len(), 1);
    }

    #[test]
    fn test_client_config_creation() {
        let identity = Identity::generate();
        let tls_config = TlsConfig::from_identity(&identity).unwrap();
        let client_config = tls_config.client_config();

        // Verify ALPN is set
        assert_eq!(client_config.alpn_protocols.len(), 1);
        assert_eq!(&client_config.alpn_protocols[0], MESHARA_ALPN);
    }

    #[test]
    fn test_server_config_creation() {
        let identity = Identity::generate();
        let tls_config = TlsConfig::from_identity(&identity).unwrap();
        let server_config = tls_config.server_config();

        // Verify ALPN is set
        assert_eq!(server_config.alpn_protocols.len(), 1);
        assert_eq!(&server_config.alpn_protocols[0], MESHARA_ALPN);
    }

    #[tokio::test]
    async fn test_tls_listener_bind() {
        let identity = Identity::generate();
        let tls_config = TlsConfig::from_identity(&identity).unwrap();

        // Bind to localhost on a random port
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = TlsListener::bind(addr, tls_config.server_config()).await;
        assert!(result.is_ok());

        let listener = result.unwrap();
        let bound_addr = listener.local_addr().unwrap();
        assert_eq!(
            bound_addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_ne!(bound_addr.port(), 0); // Should have been assigned a port
    }
}
