//! Query/response protocol for communicating with authorities
//!
//! This module provides structures and functions for querying authority nodes
//! and handling their responses.

use serde::{Deserialize, Serialize};

/// Types of queries that can be sent to authorities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QueryType {
    /// Check what the latest version is
    VersionCheck,

    /// Check if an update is available for the current version
    UpdateAvailable {
        /// The currently installed version
        current_version: String,
    },

    /// Query the operational status of the authority node
    NodeStatus,

    /// Custom query type for extensibility
    ///
    /// The String contains the custom query type identifier.
    Custom(String),
}

impl QueryType {
    /// Convert query type to string representation
    pub fn as_str(&self) -> &str {
        match self {
            QueryType::VersionCheck => "version_check",
            QueryType::UpdateAvailable { .. } => "update_available",
            QueryType::NodeStatus => "node_status",
            QueryType::Custom(s) => s.as_str(),
        }
    }
}

impl std::fmt::Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Information about an available update
///
/// This is returned in response to UpdateAvailable queries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateInfo {
    /// Version of the available update
    pub version: String,
    /// Changelog describing the changes
    pub changelog: String,
    /// Size of the update package in bytes
    pub size: usize,
    /// Whether this is a critical/required update
    pub critical: bool,
}

/// Response to a query
///
/// This is what query handlers return when responding to queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryResponse {
    /// Query succeeded with response data
    Success(Vec<u8>),

    /// Requested resource not found
    NotFound,

    /// Query failed with error message
    Error(String),
}

impl QueryResponse {
    /// Create a success response from serializable data
    ///
    /// # Arguments
    /// * `data` - The data to serialize and return
    pub fn success<T: Serialize>(data: &T) -> crate::error::Result<Self> {
        let bytes = serde_json::to_vec(data).map_err(|e| {
            crate::error::ProtocolError::SerializationFailed {
                message_type: "QueryResponse".to_string(),
                reason: e.to_string(),
            }
        })?;
        Ok(QueryResponse::Success(bytes))
    }

    /// Extract data from success response
    ///
    /// Returns None if response is not Success variant.
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            QueryResponse::Success(data) => Some(data),
            _ => None,
        }
    }

    /// Check if response is successful
    pub fn is_success(&self) -> bool {
        matches!(self, QueryResponse::Success(_))
    }

    /// Check if response is error
    pub fn is_error(&self) -> bool {
        matches!(self, QueryResponse::Error(_))
    }
}

/// Event delivered when a query is received
///
/// Query handlers receive this event and return a QueryResponse.
#[derive(Debug, Clone)]
pub struct QueryEvent {
    /// Unique query identifier
    pub query_id: Vec<u8>,
    /// Type of query as string
    pub query_type: String,
    /// Serialized query data
    pub query_data: Vec<u8>,
    /// Public key of the requester
    pub requester: crate::crypto::PublicKey,
}

impl QueryEvent {
    /// Parse the query data as a specific type
    ///
    /// # Arguments
    /// * None, uses the query_data field
    pub fn parse_data<T: for<'de> Deserialize<'de>>(&self) -> crate::error::Result<T> {
        serde_json::from_slice(&self.query_data).map_err(|e| {
            crate::error::ProtocolError::DeserializationFailed {
                reason: e.to_string(),
            }
            .into()
        })
    }
}

/// Generate a random query ID
///
/// Query IDs are 16-byte random values used to correlate requests and responses.
pub fn generate_query_id() -> Vec<u8> {
    use rand::RngCore;
    let mut id = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_type_as_str() {
        assert_eq!(QueryType::VersionCheck.as_str(), "version_check");
        assert_eq!(
            QueryType::UpdateAvailable {
                current_version: "1.0.0".to_string()
            }
            .as_str(),
            "update_available"
        );
        assert_eq!(QueryType::NodeStatus.as_str(), "node_status");
        assert_eq!(
            QueryType::Custom("custom_query".to_string()).as_str(),
            "custom_query"
        );
    }

    #[test]
    fn test_query_type_display() {
        let query = QueryType::VersionCheck;
        assert_eq!(format!("{}", query), "version_check");
    }

    #[test]
    fn test_query_type_serialization() {
        let query = QueryType::UpdateAvailable {
            current_version: "1.0.0".to_string(),
        };

        let serialized = serde_json::to_string(&query).unwrap();
        let deserialized: QueryType = serde_json::from_str(&serialized).unwrap();

        assert_eq!(query, deserialized);
    }

    #[test]
    fn test_update_info() {
        let info = UpdateInfo {
            version: "2.0.0".to_string(),
            changelog: "Major update".to_string(),
            size: 1024000,
            critical: true,
        };

        let serialized = serde_json::to_string(&info).unwrap();
        let deserialized: UpdateInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(info, deserialized);
    }

    #[test]
    fn test_query_response_success() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestData {
            value: String,
        }

        let data = TestData {
            value: "test".to_string(),
        };

        let response = QueryResponse::success(&data).unwrap();

        assert!(response.is_success());
        assert!(!response.is_error());

        let bytes = response.data().unwrap();
        let decoded: TestData = serde_json::from_slice(bytes).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_query_response_not_found() {
        let response = QueryResponse::NotFound;

        assert!(!response.is_success());
        assert!(!response.is_error());
        assert!(response.data().is_none());
    }

    #[test]
    fn test_query_response_error() {
        let response = QueryResponse::Error("Something went wrong".to_string());

        assert!(!response.is_success());
        assert!(response.is_error());
        assert!(response.data().is_none());
    }

    #[test]
    fn test_generate_query_id() {
        let id1 = generate_query_id();
        let id2 = generate_query_id();

        assert_eq!(id1.len(), 16);
        assert_eq!(id2.len(), 16);
        assert_ne!(id1, id2); // Should be different (statistically)
    }

    #[test]
    fn test_query_event_parse_data() {
        use crate::crypto::Identity;

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestQuery {
            field: String,
        }

        let query_data = TestQuery {
            field: "value".to_string(),
        };

        let identity = Identity::generate();

        let event = QueryEvent {
            query_id: vec![1, 2, 3, 4],
            query_type: "test".to_string(),
            query_data: serde_json::to_vec(&query_data).unwrap(),
            requester: identity.public_key(),
        };

        let parsed: TestQuery = event.parse_data().unwrap();
        assert_eq!(parsed, query_data);
    }

    #[test]
    fn test_query_event_parse_data_invalid() {
        use crate::crypto::Identity;

        #[derive(Deserialize)]
        struct TestQuery {
            _field: String,
        }

        let identity = Identity::generate();

        let event = QueryEvent {
            query_id: vec![1, 2, 3, 4],
            query_type: "test".to_string(),
            query_data: vec![0xFF, 0xFF], // Invalid JSON
            requester: identity.public_key(),
        };

        let result: crate::error::Result<TestQuery> = event.parse_data();
        assert!(result.is_err());
    }

    #[test]
    fn test_query_response_serialization() {
        let response = QueryResponse::Success(vec![1, 2, 3, 4]);

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: QueryResponse = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            QueryResponse::Success(data) => assert_eq!(data, vec![1, 2, 3, 4]),
            _ => panic!("Expected Success variant"),
        }
    }

    #[test]
    fn test_all_query_types_unique_strings() {
        // Check that different base types have different string representations
        assert_ne!(
            QueryType::VersionCheck.as_str(),
            QueryType::NodeStatus.as_str()
        );
        assert_ne!(
            QueryType::VersionCheck.as_str(),
            QueryType::UpdateAvailable {
                current_version: "1.0.0".to_string()
            }
            .as_str()
        );
    }
}
