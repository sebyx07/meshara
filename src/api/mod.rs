//! High-level API for Meshara

use crate::Result;

/// Main node instance
pub struct Node {
    // TODO: Implementation
}

impl Node {
    /// Start the node's networking
    pub async fn start(&self) -> Result<()> {
        todo!("Node::start not yet implemented")
    }
}

/// Builder for creating Node instances
pub struct NodeBuilder {
    storage_path: Option<String>,
}

impl NodeBuilder {
    /// Create a new NodeBuilder with default settings
    pub fn new() -> Self {
        Self {
            storage_path: None,
        }
    }

    /// Set the storage path for the node
    pub fn with_storage_path(mut self, path: impl Into<String>) -> Self {
        self.storage_path = Some(path.into());
        self
    }

    /// Build the Node instance
    pub fn build(self) -> Result<Node> {
        Ok(Node {})
    }
}

impl Default for NodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}
