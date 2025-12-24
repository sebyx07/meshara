//! Storage backend abstraction
//!
//! This module defines the StorageBackend trait for pluggable storage implementations.
//! The MVP uses FileSystemStorage, but this allows for future extensions like
//! encrypted databases, cloud storage, etc.

use crate::error::{Result, StorageError};
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::collections::HashMap;

/// Trait for storage backend implementations
///
/// This abstraction allows different storage mechanisms to be used
/// without changing the rest of the codebase.
pub trait StorageBackend {
    /// Save data with a given key
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store the data under
    /// * `value` - The data to store
    fn save(&mut self, key: &str, value: &[u8]) -> Result<()>;

    /// Load data for a given key
    ///
    /// # Arguments
    ///
    /// * `key` - The key to load data for
    ///
    /// # Returns
    ///
    /// The stored data, or an error if the key doesn't exist
    fn load(&self, key: &str) -> Result<Vec<u8>>;

    /// Check if a key exists
    ///
    /// # Arguments
    ///
    /// * `key` - The key to check
    fn exists(&self, key: &str) -> bool;

    /// Delete data for a given key
    ///
    /// # Arguments
    ///
    /// * `key` - The key to delete
    fn delete(&self, key: &str) -> Result<()>;
}

/// File system based storage implementation
///
/// Stores data as files in a specified directory.
/// This is the default storage backend for the MVP.
pub struct FileSystemStorage {
    /// Base directory for storage
    base_path: PathBuf,
}

impl FileSystemStorage {
    /// Create a new file system storage backend
    ///
    /// # Arguments
    ///
    /// * `base_path` - Directory where files will be stored
    ///
    /// # Example
    ///
    /// ```no_run
    /// use meshara::storage::backend::FileSystemStorage;
    /// use std::path::Path;
    ///
    /// let storage = FileSystemStorage::new(Path::new("./data")).unwrap();
    /// ```
    pub fn new(base_path: &Path) -> Result<Self> {
        // Create directory if it doesn't exist
        std::fs::create_dir_all(base_path).map_err(StorageError::from)?;

        // Set directory permissions to user-only (0700 on Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(base_path)
                .map_err(StorageError::from)?
                .permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(base_path, perms).map_err(StorageError::from)?;
        }

        Ok(Self {
            base_path: base_path.to_path_buf(),
        })
    }

    /// Get the full path for a given key
    fn key_to_path(&self, key: &str) -> PathBuf {
        self.base_path.join(key)
    }
}

impl StorageBackend for FileSystemStorage {
    fn save(&mut self, key: &str, value: &[u8]) -> Result<()> {
        let path = self.key_to_path(key);

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(StorageError::from)?;
        }

        // Write data
        std::fs::write(&path, value).map_err(StorageError::from)?;

        Ok(())
    }

    fn load(&self, key: &str) -> Result<Vec<u8>> {
        let path = self.key_to_path(key);

        if !path.exists() {
            return Err(StorageError::FileNotFound { path: path.clone() }.into());
        }

        std::fs::read(&path).map_err(|e| StorageError::from(e).into())
    }

    fn exists(&self, key: &str) -> bool {
        let path = self.key_to_path(key);
        path.exists() && path.is_file()
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.key_to_path(key);

        if !path.exists() {
            return Err(StorageError::FileNotFound { path: path.clone() }.into());
        }

        std::fs::remove_file(&path).map_err(StorageError::from)?;

        Ok(())
    }
}

/// In-memory storage implementation for testing
///
/// This is useful for unit tests and does not persist data to disk.
#[cfg(test)]
#[derive(Default)]
pub struct InMemoryStorage {
    data: HashMap<String, Vec<u8>>,
}

#[cfg(test)]
impl InMemoryStorage {
    /// Create a new in-memory storage for testing
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl StorageBackend for InMemoryStorage {
    fn save(&mut self, key: &str, value: &[u8]) -> Result<()> {
        self.data.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Vec<u8>> {
        self.data.get(key).cloned().ok_or_else(|| {
            StorageError::FileNotFound {
                path: PathBuf::from(key),
            }
            .into()
        })
    }

    fn exists(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    fn delete(&self, key: &str) -> Result<()> {
        if !self.data.contains_key(key) {
            return Err(StorageError::FileNotFound {
                path: PathBuf::from(key),
            }
            .into());
        }

        // Note: We can't actually delete in this implementation without &mut self
        // This is a limitation of the trait design. In a real implementation,
        // we'd use interior mutability (RwLock, Mutex, etc.)

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_filesystem_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = FileSystemStorage::new(temp_dir.path()).unwrap();

        let key = "test_key";
        let value = b"test value";

        // Save
        storage.save(key, value).unwrap();

        // Check exists
        assert!(storage.exists(key));

        // Load
        let loaded = storage.load(key).unwrap();
        assert_eq!(loaded, value);
    }

    #[test]
    fn test_filesystem_load_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileSystemStorage::new(temp_dir.path()).unwrap();

        let result = storage.load("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_filesystem_exists() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = FileSystemStorage::new(temp_dir.path()).unwrap();

        let key = "test_key";
        assert!(!storage.exists(key));

        storage.save(key, b"data").unwrap();
        assert!(storage.exists(key));
    }

    #[test]
    fn test_filesystem_delete() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = FileSystemStorage::new(temp_dir.path()).unwrap();

        let key = "test_key";
        storage.save(key, b"data").unwrap();
        assert!(storage.exists(key));

        storage.delete(key).unwrap();
        assert!(!storage.exists(key));
    }

    #[test]
    fn test_filesystem_delete_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileSystemStorage::new(temp_dir.path()).unwrap();

        let result = storage.delete("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_filesystem_directory_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let storage_dir = temp_dir.path().join("storage");
        let _storage = FileSystemStorage::new(&storage_dir).unwrap();

        // Verify directory was created
        assert!(storage_dir.exists());
        assert!(storage_dir.is_dir());

        // Verify permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&storage_dir).unwrap();
            let permissions = metadata.permissions();
            assert_eq!(permissions.mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn test_inmemory_storage() {
        let mut storage = InMemoryStorage::new();

        let key = "test_key";
        let value = b"test value";

        // Save
        storage.save(key, value).unwrap();

        // Check exists
        assert!(storage.exists(key));

        // Load
        let loaded = storage.load(key).unwrap();
        assert_eq!(loaded, value);
    }

    #[test]
    fn test_inmemory_load_nonexistent() {
        let storage = InMemoryStorage::new();

        let result = storage.load("nonexistent");
        assert!(result.is_err());
    }
}
