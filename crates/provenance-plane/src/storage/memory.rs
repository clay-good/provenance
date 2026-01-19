//! In-memory storage backend
//!
//! Default storage implementation using in-memory hashmaps.
//! Suitable for development and single-instance deployments.
//! Data is lost on restart.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::info;

use super::{CatInfo, ExecutorInfo, KeyStore, RevocationEntry, StorageError};

/// In-memory key store implementation
#[derive(Debug)]
pub struct MemoryStore {
    executors: RwLock<HashMap<String, ExecutorInfo>>,
    cats: RwLock<HashMap<String, CatInfo>>,
    revocations: RwLock<HashMap<Vec<u8>, RevocationEntry>>,
    principal_revocations: RwLock<HashMap<String, RevocationEntry>>,
}

impl MemoryStore {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self {
            executors: RwLock::new(HashMap::new()),
            cats: RwLock::new(HashMap::new()),
            revocations: RwLock::new(HashMap::new()),
            principal_revocations: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyStore for MemoryStore {
    // =========================================================================
    // Executor Key Management
    // =========================================================================

    async fn register_executor(&self, info: ExecutorInfo) -> Result<(), StorageError> {
        let mut executors = self.executors.write().unwrap();
        info!(kid = %info.kid, "Registering executor key");
        executors.insert(info.kid.clone(), info);
        Ok(())
    }

    async fn get_executor(&self, kid: &str) -> Result<Option<ExecutorInfo>, StorageError> {
        let executors = self.executors.read().unwrap();
        Ok(executors.get(kid).cloned())
    }

    async fn unregister_executor(&self, kid: &str) -> Result<bool, StorageError> {
        let mut executors = self.executors.write().unwrap();
        let removed = executors.remove(kid).is_some();
        if removed {
            info!(kid = %kid, "Unregistered executor key");
        }
        Ok(removed)
    }

    async fn list_executors(&self) -> Result<Vec<String>, StorageError> {
        let executors = self.executors.read().unwrap();
        Ok(executors.keys().cloned().collect())
    }

    // =========================================================================
    // CAT Key Management
    // =========================================================================

    async fn register_cat(&self, info: CatInfo) -> Result<(), StorageError> {
        let mut cats = self.cats.write().unwrap();
        info!(
            kid = %info.kid,
            name = ?info.name,
            endpoint = ?info.endpoint,
            is_local = info.is_local,
            "Registering CAT key"
        );
        cats.insert(info.kid.clone(), info);
        Ok(())
    }

    async fn get_cat(&self, kid: &str) -> Result<Option<CatInfo>, StorageError> {
        let cats = self.cats.read().unwrap();
        Ok(cats.get(kid).cloned())
    }

    async fn unregister_cat(&self, kid: &str) -> Result<bool, StorageError> {
        let mut cats = self.cats.write().unwrap();
        let removed = cats.remove(kid).is_some();
        if removed {
            info!(kid = %kid, "Unregistered CAT key");
        }
        Ok(removed)
    }

    async fn list_cats(&self) -> Result<Vec<String>, StorageError> {
        let cats = self.cats.read().unwrap();
        Ok(cats.keys().cloned().collect())
    }

    async fn list_federated_cats(&self) -> Result<Vec<CatInfo>, StorageError> {
        let cats = self.cats.read().unwrap();
        Ok(cats
            .values()
            .filter(|c| !c.is_local)
            .cloned()
            .collect())
    }

    // =========================================================================
    // Revocation Management
    // =========================================================================

    async fn revoke(&self, entry: RevocationEntry) -> Result<(), StorageError> {
        if let Some(ref principal) = entry.principal {
            let mut principal_revocations = self.principal_revocations.write().unwrap();
            info!(principal = %principal, reason = %entry.reason, "Revoking principal");
            principal_revocations.insert(principal.clone(), entry.clone());
        }

        let mut revocations = self.revocations.write().unwrap();
        info!(
            pca_hash = ?hex::encode(&entry.pca_hash),
            reason = %entry.reason,
            "Adding revocation"
        );
        revocations.insert(entry.pca_hash.clone(), entry);
        Ok(())
    }

    async fn is_revoked(&self, pca_hash: &[u8]) -> Result<bool, StorageError> {
        let revocations = self.revocations.read().unwrap();
        Ok(revocations.contains_key(pca_hash))
    }

    async fn is_principal_revoked(&self, principal: &str) -> Result<bool, StorageError> {
        let principal_revocations = self.principal_revocations.read().unwrap();
        Ok(principal_revocations.contains_key(principal))
    }

    async fn get_revocation(&self, pca_hash: &[u8]) -> Result<Option<RevocationEntry>, StorageError> {
        let revocations = self.revocations.read().unwrap();
        Ok(revocations.get(pca_hash).cloned())
    }

    async fn list_revocations(&self) -> Result<Vec<RevocationEntry>, StorageError> {
        let revocations = self.revocations.read().unwrap();
        Ok(revocations.values().cloned().collect())
    }
}

// Add hex encoding for debug output
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn test_executor_registration() {
        let store = MemoryStore::new();

        let info = ExecutorInfo {
            kid: "exec-1".to_string(),
            public_key: vec![0u8; 32],
            service_name: Some("test-service".to_string()),
            registered_at: Utc::now(),
            expires_at: None,
        };

        store.register_executor(info).await.unwrap();

        let retrieved = store.get_executor("exec-1").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().kid, "exec-1");

        let kids = store.list_executors().await.unwrap();
        assert!(kids.contains(&"exec-1".to_string()));
    }

    #[tokio::test]
    async fn test_cat_registration() {
        let store = MemoryStore::new();

        let local_cat = CatInfo {
            kid: "local-cat".to_string(),
            public_key: vec![0u8; 32],
            name: Some("Local Trust Plane".to_string()),
            endpoint: None,
            registered_at: Utc::now(),
            is_local: true,
        };

        let federated_cat = CatInfo {
            kid: "federated-cat".to_string(),
            public_key: vec![1u8; 32],
            name: Some("Partner Trust Plane".to_string()),
            endpoint: Some("https://partner.example.com".to_string()),
            registered_at: Utc::now(),
            is_local: false,
        };

        store.register_cat(local_cat).await.unwrap();
        store.register_cat(federated_cat).await.unwrap();

        let federated = store.list_federated_cats().await.unwrap();
        assert_eq!(federated.len(), 1);
        assert_eq!(federated[0].kid, "federated-cat");
    }

    #[tokio::test]
    async fn test_revocation() {
        let store = MemoryStore::new();

        let entry = RevocationEntry {
            pca_hash: vec![1, 2, 3, 4],
            principal: Some("alice".to_string()),
            reason: "Compromised".to_string(),
            revoked_by: "admin".to_string(),
            revoked_at: Utc::now(),
        };

        store.revoke(entry).await.unwrap();

        assert!(store.is_revoked(&[1, 2, 3, 4]).await.unwrap());
        assert!(!store.is_revoked(&[5, 6, 7, 8]).await.unwrap());
        assert!(store.is_principal_revoked("alice").await.unwrap());
        assert!(!store.is_principal_revoked("bob").await.unwrap());
    }
}
