//! Update distribution and caching system
//!
//! This module provides efficient update distribution through gossip-based propagation,
//! chunked downloads with resume capability, and peer-to-peer content delivery.

use crate::error::{AuthorityError, Result};
use crate::protocol::{UpdateAnnouncement, UpdateChunk, UpdateRequest};
use bitvec::prelude::*;
use blake3;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Size of each update chunk (64KB)
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Maximum cache size (100MB default)
pub const DEFAULT_MAX_CACHE_SIZE: usize = 100 * 1024 * 1024;

/// Update identifier (Blake3 hash of package data)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpdateId(Vec<u8>);

impl UpdateId {
    /// Create update ID from package data
    pub fn from_package_data(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(hash.as_bytes().to_vec())
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl std::fmt::Display for UpdateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Download state for an update
#[derive(Debug, Clone, PartialEq)]
pub enum DownloadState {
    /// Download has not started
    Pending,
    /// Currently downloading
    Downloading {
        /// Progress from 0.0 to 1.0
        progress: f32,
    },
    /// Verifying downloaded data
    Verifying,
    /// Download complete
    Complete,
    /// Download failed
    Failed {
        /// Reason for failure
        reason: String,
    },
}

/// Update downloader with chunked download support
pub struct UpdateDownloader {
    /// Unique update identifier
    update_id: UpdateId,
    /// Total size in bytes
    total_size: usize,
    /// Total number of chunks
    total_chunks: u32,
    /// Bitmap tracking which chunks have been received
    received_chunks: Arc<Mutex<BitVec>>,
    /// Storage for chunk data
    chunk_data: Arc<Mutex<HashMap<u32, Vec<u8>>>>,
    /// Current download state
    state: Arc<Mutex<DownloadState>>,
}

impl UpdateDownloader {
    /// Create a new update downloader
    ///
    /// # Arguments
    /// * `update_id` - Unique identifier for this update
    /// * `total_size` - Total size of the update in bytes
    pub fn new(update_id: UpdateId, total_size: usize) -> Self {
        let total_chunks = total_size.div_ceil(CHUNK_SIZE) as u32;
        let received_chunks = Arc::new(Mutex::new(bitvec![0; total_chunks as usize]));
        let chunk_data = Arc::new(Mutex::new(HashMap::new()));
        let state = Arc::new(Mutex::new(DownloadState::Pending));

        Self {
            update_id,
            total_size,
            total_chunks,
            received_chunks,
            chunk_data,
            state,
        }
    }

    /// Mark a chunk as received
    ///
    /// # Arguments
    /// * `chunk_index` - Index of the chunk
    /// * `data` - Chunk data
    /// * `chunk_hash` - Expected hash of the chunk
    pub fn mark_chunk_received(
        &self,
        chunk_index: u32,
        data: Vec<u8>,
        chunk_hash: &[u8],
    ) -> Result<()> {
        // Verify chunk hash
        let computed_hash = blake3::hash(&data);
        if computed_hash.as_bytes() != chunk_hash {
            return Err(AuthorityError::UpdateVerificationFailed {
                reason: format!("Chunk {} hash mismatch", chunk_index),
            }
            .into());
        }

        // Store chunk data
        {
            let mut chunks = self.chunk_data.lock();
            chunks.insert(chunk_index, data);
        }

        // Mark as received
        {
            let mut bits = self.received_chunks.lock();
            bits.set(chunk_index as usize, true);
        }

        // Update progress
        self.update_progress();

        Ok(())
    }

    /// Get current download progress (0.0 to 1.0)
    pub fn progress(&self) -> f32 {
        let bits = self.received_chunks.lock();
        let received = bits.count_ones();
        received as f32 / self.total_chunks as f32
    }

    /// Update the download state with current progress
    fn update_progress(&self) {
        let progress = self.progress();
        let mut state = self.state.lock();

        if progress >= 1.0 {
            *state = DownloadState::Complete;
        } else {
            *state = DownloadState::Downloading { progress };
        }
    }

    /// Check if download is complete
    pub fn is_complete(&self) -> bool {
        let bits = self.received_chunks.lock();
        bits.all()
    }

    /// Get the current state
    pub fn state(&self) -> DownloadState {
        self.state.lock().clone()
    }

    /// Set state to failed
    pub fn set_failed(&self, reason: String) {
        let mut state = self.state.lock();
        *state = DownloadState::Failed { reason };
    }

    /// Get list of missing chunk indices
    pub fn missing_chunks(&self) -> Vec<u32> {
        let bits = self.received_chunks.lock();
        (0..self.total_chunks)
            .filter(|&idx| !bits[idx as usize])
            .collect()
    }

    /// Assemble all chunks into complete package data
    pub async fn assemble(&self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            return Err(AuthorityError::UpdateVerificationFailed {
                reason: "Download incomplete".to_string(),
            }
            .into());
        }

        // Set state to verifying
        {
            let mut state = self.state.lock();
            *state = DownloadState::Verifying;
        }

        // Assemble chunks in order
        let mut assembled = Vec::with_capacity(self.total_size);
        let chunks = self.chunk_data.lock();

        for chunk_idx in 0..self.total_chunks {
            let chunk_data =
                chunks
                    .get(&chunk_idx)
                    .ok_or_else(|| AuthorityError::UpdateVerificationFailed {
                        reason: format!("Missing chunk {}", chunk_idx),
                    })?;

            assembled.extend_from_slice(chunk_data);
        }

        // Verify total size
        if assembled.len() != self.total_size {
            return Err(AuthorityError::UpdateVerificationFailed {
                reason: format!(
                    "Size mismatch: expected {}, got {}",
                    self.total_size,
                    assembled.len()
                ),
            }
            .into());
        }

        // Verify update ID matches
        let computed_id = UpdateId::from_package_data(&assembled);
        if computed_id != self.update_id {
            return Err(AuthorityError::UpdateVerificationFailed {
                reason: "Update ID mismatch after assembly".to_string(),
            }
            .into());
        }

        Ok(assembled)
    }

    /// Get the update ID
    pub fn update_id(&self) -> &UpdateId {
        &self.update_id
    }

    /// Get total chunks
    pub fn total_chunks(&self) -> u32 {
        self.total_chunks
    }
}

/// Cache for storing and serving downloaded updates
pub struct UpdateCache {
    /// Directory for cached updates
    cache_dir: PathBuf,
    /// Maximum cache size in bytes
    max_cache_size: usize,
    /// Current cache size
    current_size: Arc<AtomicUsize>,
}

impl UpdateCache {
    /// Create a new update cache
    ///
    /// # Arguments
    /// * `cache_dir` - Directory to store cached updates
    /// * `max_cache_size` - Maximum cache size in bytes
    pub fn new(cache_dir: PathBuf, max_cache_size: usize) -> Self {
        Self {
            cache_dir,
            max_cache_size,
            current_size: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Initialize the cache (create directory if needed)
    pub async fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.cache_dir).await.map_err(|e| {
            AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to create cache directory: {}", e),
            }
        })?;

        // Calculate current cache size
        self.recalculate_cache_size().await?;

        Ok(())
    }

    /// Store an update in the cache
    ///
    /// # Arguments
    /// * `update_id` - Update identifier
    /// * `data` - Update package data
    pub async fn store_update(&self, update_id: &UpdateId, data: &[u8]) -> Result<()> {
        let path = self.get_update_path(update_id);

        // Write to temporary file first
        let temp_path = path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path).await.map_err(|e| {
            AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to create cache file: {}", e),
            }
        })?;

        file.write_all(data)
            .await
            .map_err(|e| AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to write cache file: {}", e),
            })?;

        // Rename to final location (atomic operation)
        fs::rename(&temp_path, &path).await.map_err(|e| {
            AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to rename cache file: {}", e),
            }
        })?;

        // Update cache size
        self.current_size.fetch_add(data.len(), Ordering::Relaxed);

        // Check if we need to evict old updates
        self.evict_if_needed().await?;

        Ok(())
    }

    /// Check if an update is in the cache
    pub async fn has_update(&self, update_id: &UpdateId) -> bool {
        let path = self.get_update_path(update_id);
        path.exists()
    }

    /// Load an update from the cache
    ///
    /// # Arguments
    /// * `update_id` - Update identifier
    pub async fn load_update(&self, update_id: &UpdateId) -> Result<Vec<u8>> {
        let path = self.get_update_path(update_id);

        let mut file =
            fs::File::open(&path)
                .await
                .map_err(|e| AuthorityError::UpdateVerificationFailed {
                    reason: format!("Failed to open cache file: {}", e),
                })?;

        let mut data = Vec::new();
        file.read_to_end(&mut data).await.map_err(|e| {
            AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to read cache file: {}", e),
            }
        })?;

        // Verify hash matches update_id
        let computed_id = UpdateId::from_package_data(&data);
        if computed_id != *update_id {
            return Err(AuthorityError::UpdateVerificationFailed {
                reason: "Cached update hash mismatch".to_string(),
            }
            .into());
        }

        Ok(data)
    }

    /// Serve a specific chunk from a cached update
    ///
    /// # Arguments
    /// * `update_id` - Update identifier
    /// * `chunk_index` - Chunk index to serve
    pub async fn serve_chunk(&self, update_id: &UpdateId, chunk_index: u32) -> Result<UpdateChunk> {
        // Load the complete update
        let data = self.load_update(update_id).await?;

        // Calculate chunk boundaries
        let start = (chunk_index as usize) * CHUNK_SIZE;
        let end = std::cmp::min(start + CHUNK_SIZE, data.len());

        if start >= data.len() {
            return Err(AuthorityError::UpdateVerificationFailed {
                reason: format!("Chunk index {} out of bounds", chunk_index),
            }
            .into());
        }

        // Extract chunk data
        let chunk_data = data[start..end].to_vec();
        let chunk_hash = blake3::hash(&chunk_data);

        // Calculate total chunks
        let total_chunks = data.len().div_ceil(CHUNK_SIZE) as u32;

        Ok(UpdateChunk {
            update_id: update_id.as_bytes().to_vec(),
            chunk_index,
            total_chunks,
            data: chunk_data,
            chunk_hash: chunk_hash.as_bytes().to_vec(),
        })
    }

    /// Get the file path for an update
    fn get_update_path(&self, update_id: &UpdateId) -> PathBuf {
        self.cache_dir.join(format!("{}.pkg", update_id.to_hex()))
    }

    /// Recalculate the total cache size
    async fn recalculate_cache_size(&self) -> Result<()> {
        let mut total_size = 0;

        let mut entries = fs::read_dir(&self.cache_dir).await.map_err(|e| {
            AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to read cache directory: {}", e),
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
                total_size += metadata.len() as usize;
            }
        }

        self.current_size.store(total_size, Ordering::Relaxed);
        Ok(())
    }

    /// Evict old updates if cache is over size limit
    async fn evict_if_needed(&self) -> Result<()> {
        while self.current_size.load(Ordering::Relaxed) > self.max_cache_size {
            // Find oldest file
            let oldest = self.find_oldest_update().await?;

            if let Some((path, size)) = oldest {
                // Remove the file
                fs::remove_file(&path).await.map_err(|e| {
                    AuthorityError::UpdateVerificationFailed {
                        reason: format!("Failed to remove cache file: {}", e),
                    }
                })?;

                // Update cache size
                self.current_size.fetch_sub(size, Ordering::Relaxed);
            } else {
                // No files to evict
                break;
            }
        }

        Ok(())
    }

    /// Find the oldest update in the cache
    async fn find_oldest_update(&self) -> Result<Option<(PathBuf, usize)>> {
        let mut entries = fs::read_dir(&self.cache_dir).await.map_err(|e| {
            AuthorityError::UpdateVerificationFailed {
                reason: format!("Failed to read cache directory: {}", e),
            }
        })?;

        let mut oldest: Option<(PathBuf, usize, std::time::SystemTime)> = None;

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
                    let size = metadata.len() as usize;
                    let path = entry.path();

                    if let Some((_, _, oldest_time)) = oldest {
                        if modified < oldest_time {
                            oldest = Some((path, size, modified));
                        }
                    } else {
                        oldest = Some((path, size, modified));
                    }
                }
            }
        }

        Ok(oldest.map(|(path, size, _)| (path, size)))
    }

    /// Get current cache size in bytes
    pub fn current_size(&self) -> usize {
        self.current_size.load(Ordering::Relaxed)
    }
}

/// Bandwidth limiter for rate-limiting update downloads
pub struct BandwidthLimiter {
    /// Maximum bytes per second
    max_bytes_per_second: usize,
    /// Current usage in this time window
    current_usage: Arc<AtomicUsize>,
    /// Time window in seconds
    window_seconds: u64,
}

impl BandwidthLimiter {
    /// Create a new bandwidth limiter
    ///
    /// # Arguments
    /// * `max_bytes_per_second` - Maximum bandwidth in bytes/second
    pub fn new(max_bytes_per_second: usize) -> Self {
        Self {
            max_bytes_per_second,
            current_usage: Arc::new(AtomicUsize::new(0)),
            window_seconds: 1,
        }
    }

    /// Acquire permit to transfer bytes
    ///
    /// This will wait if the current usage is too high.
    ///
    /// # Arguments
    /// * `bytes` - Number of bytes to transfer
    pub async fn acquire_permit(&self, bytes: usize) -> Result<()> {
        loop {
            let current = self.current_usage.load(Ordering::Relaxed);

            if current + bytes <= self.max_bytes_per_second {
                // Can proceed
                self.current_usage.fetch_add(bytes, Ordering::Relaxed);
                return Ok(());
            }

            // Wait a bit and try again
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    /// Start background task to reset usage counter periodically
    pub fn start_reset_loop(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(self.window_seconds));

            loop {
                interval.tick().await;
                self.current_usage.store(0, Ordering::Relaxed);
            }
        });
    }

    /// Get current usage
    pub fn current_usage(&self) -> usize {
        self.current_usage.load(Ordering::Relaxed)
    }
}

/// Helper function to create UpdateRequest message
pub fn create_update_request(update_id: &UpdateId, chunk_index: u32) -> UpdateRequest {
    UpdateRequest {
        update_id: update_id.as_bytes().to_vec(),
        chunk_index,
    }
}

/// Helper function to create UpdateAnnouncement
pub fn create_update_announcement(
    version: String,
    update_id: &UpdateId,
    size: u64,
    checksum: Vec<u8>,
    signatures: Vec<Vec<u8>>,
) -> UpdateAnnouncement {
    UpdateAnnouncement {
        version,
        update_id: update_id.as_bytes().to_vec(),
        size,
        checksum,
        signatures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_update_id_from_data() {
        let data = b"test data";
        let id1 = UpdateId::from_package_data(data);
        let id2 = UpdateId::from_package_data(data);

        assert_eq!(id1, id2);
        assert_eq!(id1.as_bytes().len(), 32); // Blake3 hash size
    }

    #[test]
    fn test_update_id_hex() {
        let data = b"test";
        let id = UpdateId::from_package_data(data);
        let hex = id.to_hex();

        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_update_downloader_creation() {
        let id = UpdateId::from_package_data(b"test");
        let downloader = UpdateDownloader::new(id, 1024);

        assert_eq!(downloader.total_size, 1024);
        assert_eq!(downloader.total_chunks, 1); // 1024 bytes = 1 chunk
        assert_eq!(downloader.progress(), 0.0);
        assert!(!downloader.is_complete());
    }

    #[test]
    fn test_update_downloader_chunk_calculation() {
        let id = UpdateId::from_package_data(b"test");
        let downloader = UpdateDownloader::new(id, CHUNK_SIZE * 2 + 100);

        assert_eq!(downloader.total_chunks, 3); // 2 full chunks + 1 partial
    }

    #[test]
    fn test_update_downloader_mark_chunk() {
        let id = UpdateId::from_package_data(b"test");
        let downloader = UpdateDownloader::new(id, CHUNK_SIZE);

        let chunk_data = vec![1, 2, 3, 4];
        let chunk_hash = blake3::hash(&chunk_data);

        let result = downloader.mark_chunk_received(0, chunk_data, chunk_hash.as_bytes());

        assert!(result.is_ok());
        assert_eq!(downloader.progress(), 1.0);
        assert!(downloader.is_complete());
    }

    #[test]
    fn test_update_downloader_invalid_hash() {
        let id = UpdateId::from_package_data(b"test");
        let downloader = UpdateDownloader::new(id, CHUNK_SIZE);

        let chunk_data = vec![1, 2, 3, 4];
        let wrong_hash = vec![0u8; 32];

        let result = downloader.mark_chunk_received(0, chunk_data, &wrong_hash);

        assert!(result.is_err());
    }

    #[test]
    fn test_update_downloader_missing_chunks() {
        let id = UpdateId::from_package_data(b"test");
        let downloader = UpdateDownloader::new(id, CHUNK_SIZE * 3);

        // Mark chunk 1 as received
        let chunk_data = vec![1, 2, 3];
        let chunk_hash = blake3::hash(&chunk_data);
        downloader
            .mark_chunk_received(1, chunk_data, chunk_hash.as_bytes())
            .unwrap();

        let missing = downloader.missing_chunks();
        assert_eq!(missing, vec![0, 2]);
    }

    #[tokio::test]
    async fn test_update_downloader_assemble() {
        let test_data = b"Hello, World!";
        let id = UpdateId::from_package_data(test_data);
        let downloader = UpdateDownloader::new(id.clone(), test_data.len());

        // Calculate single chunk hash
        let chunk_hash = blake3::hash(test_data);

        // Mark chunk as received
        downloader
            .mark_chunk_received(0, test_data.to_vec(), chunk_hash.as_bytes())
            .unwrap();

        // Assemble
        let assembled = downloader.assemble().await.unwrap();

        assert_eq!(assembled, test_data);
    }

    #[tokio::test]
    async fn test_update_cache_init() {
        let temp_dir = TempDir::new().unwrap();
        let cache = UpdateCache::new(temp_dir.path().to_path_buf(), DEFAULT_MAX_CACHE_SIZE);

        let result = cache.init().await;
        assert!(result.is_ok());
        assert!(temp_dir.path().exists());
    }

    #[tokio::test]
    async fn test_update_cache_store_load() {
        let temp_dir = TempDir::new().unwrap();
        let cache = UpdateCache::new(temp_dir.path().to_path_buf(), DEFAULT_MAX_CACHE_SIZE);
        cache.init().await.unwrap();

        let test_data = b"test update data";
        let id = UpdateId::from_package_data(test_data);

        // Store
        cache.store_update(&id, test_data).await.unwrap();

        // Check exists
        assert!(cache.has_update(&id).await);

        // Load
        let loaded = cache.load_update(&id).await.unwrap();
        assert_eq!(loaded, test_data);
    }

    #[tokio::test]
    async fn test_update_cache_serve_chunk() {
        let temp_dir = TempDir::new().unwrap();
        let cache = UpdateCache::new(temp_dir.path().to_path_buf(), DEFAULT_MAX_CACHE_SIZE);
        cache.init().await.unwrap();

        let test_data = vec![0u8; CHUNK_SIZE * 2 + 100];
        let id = UpdateId::from_package_data(&test_data);

        cache.store_update(&id, &test_data).await.unwrap();

        // Serve first chunk
        let chunk = cache.serve_chunk(&id, 0).await.unwrap();
        assert_eq!(chunk.chunk_index, 0);
        assert_eq!(chunk.total_chunks, 3);
        assert_eq!(chunk.data.len(), CHUNK_SIZE);

        // Serve last chunk (partial)
        let chunk = cache.serve_chunk(&id, 2).await.unwrap();
        assert_eq!(chunk.chunk_index, 2);
        assert_eq!(chunk.data.len(), 100);
    }

    #[test]
    fn test_bandwidth_limiter_creation() {
        let limiter = BandwidthLimiter::new(1024 * 1024); // 1 MB/s

        assert_eq!(limiter.max_bytes_per_second, 1024 * 1024);
        assert_eq!(limiter.current_usage(), 0);
    }

    #[tokio::test]
    async fn test_bandwidth_limiter_acquire() {
        let limiter = BandwidthLimiter::new(1024);

        // Should succeed
        let result = limiter.acquire_permit(512).await;
        assert!(result.is_ok());
        assert_eq!(limiter.current_usage(), 512);

        // Should succeed
        let result = limiter.acquire_permit(512).await;
        assert!(result.is_ok());
        assert_eq!(limiter.current_usage(), 1024);
    }

    #[test]
    fn test_create_update_request() {
        let id = UpdateId::from_package_data(b"test");
        let request = create_update_request(&id, 5);

        assert_eq!(request.update_id, id.as_bytes());
        assert_eq!(request.chunk_index, 5);
    }

    #[test]
    fn test_create_update_announcement() {
        let id = UpdateId::from_package_data(b"test");
        let checksum = vec![1, 2, 3];
        let signatures = vec![vec![4, 5, 6]];

        let announcement = create_update_announcement(
            "1.0.0".to_string(),
            &id,
            1024,
            checksum.clone(),
            signatures.clone(),
        );

        assert_eq!(announcement.version, "1.0.0");
        assert_eq!(announcement.update_id, id.as_bytes());
        assert_eq!(announcement.size, 1024);
        assert_eq!(announcement.checksum, checksum);
        assert_eq!(announcement.signatures, signatures);
    }
}
