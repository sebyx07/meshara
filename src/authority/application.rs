//! Update application and rollback system
//!
//! This module provides safe update application with automatic backup and rollback
//! capabilities to ensure system stability during updates.

use crate::authority::updates::verify_update_package;
use crate::authority::AuthorityTrustStore;
use crate::error::{AuthorityError, Result};
use crate::protocol::UpdatePackage;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Update applicator with backup/rollback support
pub struct UpdateApplicator {
    /// Directory for storing backups
    backup_dir: PathBuf,
    /// Current version string
    current_version: String,
    /// Path to the binary being updated
    binary_path: PathBuf,
}

impl UpdateApplicator {
    /// Create a new update applicator
    ///
    /// # Arguments
    /// * `backup_dir` - Directory to store backups
    /// * `current_version` - Current version string
    /// * `binary_path` - Path to the binary to update
    pub fn new(backup_dir: PathBuf, current_version: String, binary_path: PathBuf) -> Self {
        Self {
            backup_dir,
            current_version,
            binary_path,
        }
    }

    /// Initialize the applicator (create backup directory)
    pub async fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.backup_dir).await.map_err(|e| {
            AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to create backup directory: {}", e),
            }
        })?;

        Ok(())
    }

    /// Apply an update package safely
    ///
    /// This will:
    /// 1. Verify the update (if not already verified)
    /// 2. Backup the current binary
    /// 3. Apply the update
    /// 4. Verify the new binary works
    /// 5. Rollback on failure
    ///
    /// # Arguments
    /// * `update` - The update package to apply
    /// * `trust_store` - Trust store for verification
    /// * `min_signatures` - Minimum signatures required (if not already verified)
    pub async fn apply_update(
        &self,
        update: UpdatePackage,
        trust_store: &AuthorityTrustStore,
        min_signatures: usize,
    ) -> Result<String> {
        // Verify update package
        verify_update_package(&update, trust_store, min_signatures)?;

        // Check version compatibility
        if !self.check_version_compatibility(&update.required_version)? {
            return Err(AuthorityError::VersionMismatch {
                required: update.required_version,
                current: self.current_version.clone(),
            }
            .into());
        }

        // Backup current binary
        let backup_path = self.backup_current().await?;

        // Try to apply update
        match self.apply_binary_update(&update.package_data).await {
            Ok(_) => {
                // Verify new binary works
                match self.verify_update(&update.version).await {
                    Ok(true) => {
                        // Success!
                        Ok(update.version)
                    },
                    Ok(false) | Err(_) => {
                        // Verification failed, rollback
                        self.rollback(&backup_path).await?;
                        Err(AuthorityError::UpdateVerificationFailed {
                            reason: "New binary verification failed".to_string(),
                        }
                        .into())
                    },
                }
            },
            Err(e) => {
                // Failed to apply, rollback
                self.rollback(&backup_path).await?;
                Err(e)
            },
        }
    }

    /// Backup the current binary
    async fn backup_current(&self) -> Result<PathBuf> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let backup_filename = format!("backup_{}_{}.bin", self.current_version, timestamp);
        let backup_path = self.backup_dir.join(backup_filename);

        // Copy current binary to backup
        fs::copy(&self.binary_path, &backup_path)
            .await
            .map_err(|e| AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to create backup: {}", e),
            })?;

        Ok(backup_path)
    }

    /// Apply a binary update
    async fn apply_binary_update(&self, package_data: &[u8]) -> Result<()> {
        // Write to temporary file first
        let temp_path = self.binary_path.with_extension("new");

        let mut file = fs::File::create(&temp_path).await.map_err(|e| {
            AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to create new binary: {}", e),
            }
        })?;

        file.write_all(package_data).await.map_err(|e| {
            AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to write new binary: {}", e),
            }
        })?;

        // Set executable permissions (Unix-like systems)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&temp_path)
                .await
                .map_err(|e| AuthorityError::UpdateVerificationFailed {
                    reason: format!("Failed to get file permissions: {}", e),
                })?
                .permissions();

            perms.set_mode(0o755); // rwxr-xr-x

            fs::set_permissions(&temp_path, perms).await.map_err(|e| {
                AuthorityError::UpdateVerificationFailed {
                    reason: format!("Failed to set permissions: {}", e),
                }
            })?;
        }

        // Replace old binary with new one
        fs::rename(&temp_path, &self.binary_path)
            .await
            .map_err(|e| AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to replace binary: {}", e),
            })?;

        Ok(())
    }

    /// Verify the new binary works
    ///
    /// This runs the new binary with --version flag to check it executes correctly.
    async fn verify_update(&self, expected_version: &str) -> Result<bool> {
        // Try to run the binary with --version
        let output = Command::new(&self.binary_path)
            .arg("--version")
            .output()
            .await
            .map_err(|e| AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to execute new binary: {}", e),
            })?;

        if !output.status.success() {
            return Ok(false);
        }

        // Check version string is present in output
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.contains(expected_version))
    }

    /// Rollback to a previous backup
    pub async fn rollback(&self, backup_path: &Path) -> Result<()> {
        fs::copy(backup_path, &self.binary_path)
            .await
            .map_err(|e| AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to rollback: {}", e),
            })?;

        Ok(())
    }

    /// Check if the required version is compatible
    ///
    /// For now, this is a simple string comparison.
    /// In production, use semver parsing.
    fn check_version_compatibility(&self, required_version: &str) -> Result<bool> {
        if required_version.is_empty() {
            // No requirement
            return Ok(true);
        }

        // For MVP, allow any update if current version >= required version
        // In production, use proper semver comparison
        Ok(self.current_version.as_str() >= required_version)
    }

    /// Get the current version
    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    /// Clean up old backups, keeping only the most recent N backups
    pub async fn cleanup_old_backups(&self, keep_count: usize) -> Result<()> {
        let mut backups = Vec::new();

        let mut entries = fs::read_dir(&self.backup_dir).await.map_err(|e| {
            AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to read backup directory: {}", e),
            }
        })?;

        while let Some(entry) =
            entries
                .next_entry()
                .await
                .map_err(|e| AuthorityError::UpdateVerificationFailed {
                    reason: format!("Failed to read directory entry: {}", e),
                })?
        {
            if let Ok(metadata) = entry.metadata().await {
                if let Ok(modified) = metadata.modified() {
                    backups.push((entry.path(), modified));
                }
            }
        }

        // Sort by modification time (newest first)
        backups.sort_by(|a, b| b.1.cmp(&a.1));

        // Remove old backups
        for (path, _) in backups.iter().skip(keep_count) {
            let _ = fs::remove_file(path).await;
        }

        Ok(())
    }
}

/// Apply an update package safely with automatic rollback
///
/// This is a convenience function that creates a temporary applicator and applies the update.
///
/// # Arguments
/// * `update` - The update package
/// * `trust_store` - Trust store for verification
/// * `min_signatures` - Minimum required signatures
/// * `backup_dir` - Directory for backups
/// * `current_version` - Current version string
/// * `binary_path` - Path to binary to update
pub async fn apply_update_safely(
    update: UpdatePackage,
    trust_store: &AuthorityTrustStore,
    min_signatures: usize,
    backup_dir: PathBuf,
    current_version: String,
    binary_path: PathBuf,
) -> Result<String> {
    let applicator = UpdateApplicator::new(backup_dir, current_version, binary_path);
    applicator.init().await?;

    applicator
        .apply_update(update, trust_store, min_signatures)
        .await
}

/// Events emitted during update process
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateEvent {
    /// Update announcement received
    AnnouncementReceived {
        /// Version of the update
        version: String,
        /// Size of the update
        size: usize,
    },

    /// Download started
    DownloadStarted {
        /// Update identifier
        update_id: String,
    },

    /// Download progress update
    DownloadProgress {
        /// Update identifier
        update_id: String,
        /// Progress (0.0 to 1.0)
        progress: f32,
    },

    /// Download completed
    DownloadComplete {
        /// Update identifier
        update_id: String,
    },

    /// Verifying update
    VerifyingUpdate,

    /// Applying update
    ApplyingUpdate,

    /// Update completed successfully
    UpdateComplete {
        /// Old version
        old_version: String,
        /// New version
        new_version: String,
    },

    /// Update failed
    UpdateFailed {
        /// Failure reason
        reason: String,
    },

    /// Rolled back to previous version
    RolledBack {
        /// Version rolled back to
        version: String,
    },
}

/// Configuration for update behavior
#[derive(Debug, Clone)]
pub struct UpdateConfig {
    /// Whether to automatically check for updates
    pub auto_check: bool,

    /// Interval between update checks
    pub check_interval: std::time::Duration,

    /// Whether to automatically download updates
    pub auto_download: bool,

    /// Whether to automatically apply updates
    pub auto_apply: bool,

    /// Maximum download speed (bytes/sec), None for unlimited
    pub max_download_speed: Option<usize>,

    /// Maximum cache size for updates
    pub cache_size: usize,

    /// Directory for backups
    pub backup_dir: PathBuf,

    /// Number of backups to keep
    pub keep_backups: usize,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            auto_check: true,
            check_interval: std::time::Duration::from_secs(3600), // 1 hour
            auto_download: true,
            auto_apply: false, // Require user approval
            max_download_speed: None,
            cache_size: 100 * 1024 * 1024, // 100 MB
            backup_dir: PathBuf::from("./backups"),
            keep_backups: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_update_applicator_init() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");

        let applicator = UpdateApplicator::new(
            backup_dir.clone(),
            "1.0.0".to_string(),
            PathBuf::from("/fake/binary"),
        );

        applicator.init().await.unwrap();

        assert!(backup_dir.exists());
    }

    #[tokio::test]
    async fn test_update_applicator_backup() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");

        // Create a fake binary file
        let binary_path = temp_dir.path().join("binary");
        fs::write(&binary_path, b"fake binary content")
            .await
            .unwrap();

        let applicator =
            UpdateApplicator::new(backup_dir.clone(), "1.0.0".to_string(), binary_path.clone());
        applicator.init().await.unwrap();

        // Create backup
        let backup_path = applicator.backup_current().await.unwrap();

        assert!(backup_path.exists());

        // Verify backup content
        let backup_content = fs::read(&backup_path).await.unwrap();
        assert_eq!(backup_content, b"fake binary content");
    }

    #[tokio::test]
    async fn test_update_applicator_rollback() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");

        // Create original binary
        let binary_path = temp_dir.path().join("binary");
        fs::write(&binary_path, b"original content").await.unwrap();

        let applicator =
            UpdateApplicator::new(backup_dir.clone(), "1.0.0".to_string(), binary_path.clone());
        applicator.init().await.unwrap();

        // Create backup
        let backup_path = applicator.backup_current().await.unwrap();

        // Modify binary
        fs::write(&binary_path, b"modified content").await.unwrap();

        // Rollback
        applicator.rollback(&backup_path).await.unwrap();

        // Verify original content restored
        let content = fs::read(&binary_path).await.unwrap();
        assert_eq!(content, b"original content");
    }

    #[tokio::test]
    async fn test_update_applicator_apply_binary() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");

        // Create original binary
        let binary_path = temp_dir.path().join("binary");
        fs::write(&binary_path, b"old version").await.unwrap();

        let applicator =
            UpdateApplicator::new(backup_dir.clone(), "1.0.0".to_string(), binary_path.clone());
        applicator.init().await.unwrap();

        // Apply new binary
        applicator
            .apply_binary_update(b"new version")
            .await
            .unwrap();

        // Verify new content
        let content = fs::read(&binary_path).await.unwrap();
        assert_eq!(content, b"new version");
    }

    #[test]
    fn test_version_compatibility() {
        let applicator = UpdateApplicator::new(
            PathBuf::from("/fake"),
            "2.0.0".to_string(),
            PathBuf::from("/fake/binary"),
        );

        // Empty required version should allow update
        assert!(applicator.check_version_compatibility("").unwrap());

        // Current >= required should allow
        assert!(applicator.check_version_compatibility("1.0.0").unwrap());
        assert!(applicator.check_version_compatibility("2.0.0").unwrap());

        // Current < required should reject (with simple string comparison)
        assert!(!applicator.check_version_compatibility("3.0.0").unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_old_backups() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        fs::create_dir_all(&backup_dir).await.unwrap();

        // Create 5 backup files
        for i in 0..5 {
            let backup_path = backup_dir.join(format!("backup_{}.bin", i));
            fs::write(&backup_path, b"backup").await.unwrap();
            // Small delay to ensure different modification times
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        let applicator = UpdateApplicator::new(
            backup_dir.clone(),
            "1.0.0".to_string(),
            PathBuf::from("/fake"),
        );

        // Keep only 3 most recent
        applicator.cleanup_old_backups(3).await.unwrap();

        // Count remaining backups
        let mut count = 0;
        let mut entries = fs::read_dir(&backup_dir).await.unwrap();
        while entries.next_entry().await.unwrap().is_some() {
            count += 1;
        }

        assert_eq!(count, 3);
    }

    #[test]
    fn test_update_config_default() {
        let config = UpdateConfig::default();

        assert!(config.auto_check);
        assert!(config.auto_download);
        assert!(!config.auto_apply); // Should require approval by default
        assert_eq!(config.keep_backups, 3);
        assert_eq!(config.cache_size, 100 * 1024 * 1024);
    }

    #[test]
    fn test_update_event_types() {
        let event = UpdateEvent::AnnouncementReceived {
            version: "1.0.0".to_string(),
            size: 1024,
        };

        match event {
            UpdateEvent::AnnouncementReceived { version, size } => {
                assert_eq!(version, "1.0.0");
                assert_eq!(size, 1024);
            },
            _ => panic!("Wrong event type"),
        }
    }
}
