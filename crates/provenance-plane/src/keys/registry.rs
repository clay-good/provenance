//! Key Registry for Trust Plane
//!
//! Manages cryptographic keys for:
//! - The Trust Plane's CAT (Causal Authority Transition) signing key
//! - Registered executor public keys for PoC verification
//! - Other CAT public keys for verifying PCAs from federated Trust Planes

use provenance_core::{
    crypto::{KeyPair, PublicKey, SignedPca},
    pca::Pca,
    error::ProvenanceError,
};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::info;

/// Key Registry for the Trust Plane
///
/// Thread-safe storage for:
/// - CAT signing key (this Trust Plane's identity)
/// - Executor public keys (for verifying PoC signatures)
/// - CAT public keys (for verifying PCAs from other Trust Planes)
pub struct KeyRegistry {
    /// Registered executor public keys (kid -> key)
    executor_keys: RwLock<HashMap<String, PublicKey>>,

    /// Registered CAT public keys (kid -> key)
    /// Includes this Trust Plane's own public key
    cat_keys: RwLock<HashMap<String, PublicKey>>,

    /// This Trust Plane's CAT key pair for signing PCAs
    cat_key_pair: KeyPair,
}

impl KeyRegistry {
    /// Create a new key registry with the given CAT key pair
    ///
    /// The CAT key pair is used to sign PCAs issued by this Trust Plane.
    /// The public key is automatically registered in the CAT keys registry.
    pub fn new(cat_key_pair: KeyPair) -> Self {
        let cat_kid = cat_key_pair.kid().to_string();
        let cat_public = cat_key_pair.public_key();

        let registry = Self {
            executor_keys: RwLock::new(HashMap::new()),
            cat_keys: RwLock::new(HashMap::new()),
            cat_key_pair,
        };

        // Register our own CAT public key for self-verification
        {
            let mut cat_keys = registry.cat_keys.write().unwrap();
            cat_keys.insert(cat_kid.clone(), cat_public);
        }

        info!(kid = %cat_kid, "Key registry initialized with CAT key");

        registry
    }

    /// Generate a new key registry with a randomly generated CAT key
    pub fn generate(cat_kid: impl Into<String>) -> Self {
        let key_pair = KeyPair::generate(cat_kid);
        Self::new(key_pair)
    }

    /// Get this Trust Plane's CAT key ID
    pub fn cat_kid(&self) -> &str {
        self.cat_key_pair.kid()
    }

    /// Get this Trust Plane's CAT public key
    pub fn cat_public_key(&self) -> PublicKey {
        self.cat_key_pair.public_key()
    }

    // =========================================================================
    // Executor Key Management
    // =========================================================================

    /// Register an executor's public key
    ///
    /// Executors must register their public keys before they can submit PoCs.
    pub fn register_executor(&self, kid: String, key: PublicKey) {
        let mut executor_keys = self.executor_keys.write().unwrap();
        info!(kid = %kid, "Registered executor key");
        executor_keys.insert(kid, key);
    }

    /// Register an executor's public key from raw bytes
    pub fn register_executor_bytes(
        &self,
        kid: String,
        key_bytes: &[u8; 32],
    ) -> Result<(), ProvenanceError> {
        let key = PublicKey::from_bytes(&kid, key_bytes)?;
        self.register_executor(kid, key);
        Ok(())
    }

    /// Get an executor's public key by key ID
    pub fn get_executor(&self, kid: &str) -> Option<PublicKey> {
        let executor_keys = self.executor_keys.read().unwrap();
        executor_keys.get(kid).cloned()
    }

    /// Check if an executor key is registered
    pub fn has_executor(&self, kid: &str) -> bool {
        let executor_keys = self.executor_keys.read().unwrap();
        executor_keys.contains_key(kid)
    }

    /// Remove an executor's public key
    pub fn unregister_executor(&self, kid: &str) -> bool {
        let mut executor_keys = self.executor_keys.write().unwrap();
        let removed = executor_keys.remove(kid).is_some();
        if removed {
            info!(kid = %kid, "Unregistered executor key");
        }
        removed
    }

    /// List all registered executor key IDs
    pub fn list_executor_kids(&self) -> Vec<String> {
        let executor_keys = self.executor_keys.read().unwrap();
        executor_keys.keys().cloned().collect()
    }

    /// Get the number of registered executor keys
    pub fn executor_count(&self) -> usize {
        let executor_keys = self.executor_keys.read().unwrap();
        executor_keys.len()
    }

    // =========================================================================
    // CAT Key Management
    // =========================================================================

    /// Register another Trust Plane's CAT public key
    ///
    /// Used for federation - verifying PCAs signed by other Trust Planes.
    pub fn register_cat(&self, kid: String, key: PublicKey) {
        let mut cat_keys = self.cat_keys.write().unwrap();
        info!(kid = %kid, "Registered CAT key");
        cat_keys.insert(kid, key);
    }

    /// Get a CAT's public key by key ID
    pub fn get_cat(&self, kid: &str) -> Option<PublicKey> {
        let cat_keys = self.cat_keys.read().unwrap();
        cat_keys.get(kid).cloned()
    }

    /// Check if a CAT key is registered
    pub fn has_cat(&self, kid: &str) -> bool {
        let cat_keys = self.cat_keys.read().unwrap();
        cat_keys.contains_key(kid)
    }

    /// List all registered CAT key IDs
    pub fn list_cat_kids(&self) -> Vec<String> {
        let cat_keys = self.cat_keys.read().unwrap();
        cat_keys.keys().cloned().collect()
    }

    // =========================================================================
    // Signing Operations
    // =========================================================================

    /// Sign a PCA with this Trust Plane's CAT key
    pub fn sign_pca(&self, pca: &Pca) -> Result<SignedPca, ProvenanceError> {
        self.cat_key_pair.sign_pca(pca)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use provenance_core::{
        pca::{ExecutorBinding, PcaBuilder},
        types::PrincipalIdentifier,
    };

    #[test]
    fn test_registry_creation() {
        let registry = KeyRegistry::generate("test-cat");
        assert_eq!(registry.cat_kid(), "test-cat");
        assert!(registry.has_cat("test-cat"));
    }

    #[test]
    fn test_executor_registration() {
        let registry = KeyRegistry::generate("test-cat");
        let executor_kp = KeyPair::generate("executor-1");

        registry.register_executor("executor-1".into(), executor_kp.public_key());

        assert!(registry.has_executor("executor-1"));
        assert!(!registry.has_executor("executor-2"));
        assert_eq!(registry.executor_count(), 1);
    }

    #[test]
    fn test_executor_list() {
        let registry = KeyRegistry::generate("test-cat");

        let kp1 = KeyPair::generate("exec-1");
        let kp2 = KeyPair::generate("exec-2");

        registry.register_executor("exec-1".into(), kp1.public_key());
        registry.register_executor("exec-2".into(), kp2.public_key());

        let kids = registry.list_executor_kids();
        assert_eq!(kids.len(), 2);
        assert!(kids.contains(&"exec-1".to_string()));
        assert!(kids.contains(&"exec-2".to_string()));
    }

    #[test]
    fn test_executor_unregister() {
        let registry = KeyRegistry::generate("test-cat");
        let kp = KeyPair::generate("exec-1");

        registry.register_executor("exec-1".into(), kp.public_key());
        assert!(registry.has_executor("exec-1"));

        registry.unregister_executor("exec-1");
        assert!(!registry.has_executor("exec-1"));
    }

    #[test]
    fn test_sign_pca() {
        let registry = KeyRegistry::generate("test-cat");

        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["read:*".into()])
            .executor(ExecutorBinding::new().with("service", "gateway"))
            .build_pca_0()
            .unwrap();

        let signed = registry.sign_pca(&pca).unwrap();

        // Verify with our own CAT key
        let cat_key = registry.get_cat(registry.cat_kid()).unwrap();
        let verified = cat_key.verify_pca(&signed).unwrap();

        assert_eq!(verified, pca);
    }

    #[test]
    fn test_cat_federation() {
        let registry1 = KeyRegistry::generate("cat-1");
        let registry2 = KeyRegistry::generate("cat-2");

        // Register cat-2's public key in registry1
        registry1.register_cat("cat-2".into(), registry2.cat_public_key());

        assert!(registry1.has_cat("cat-2"));

        // Sign a PCA with cat-2
        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:bob"))
            .ops(vec!["write:*".into()])
            .build_pca_0()
            .unwrap();

        let signed = registry2.sign_pca(&pca).unwrap();

        // Verify with cat-2's key from registry1
        let cat2_key = registry1.get_cat("cat-2").unwrap();
        let verified = cat2_key.verify_pca(&signed).unwrap();

        assert_eq!(verified, pca);
    }
}
