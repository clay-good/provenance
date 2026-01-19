//! Cryptographic primitives for PCA/PoC signing
//!
//! This module implements COSE_Sign1 signing using Ed25519 keys.
//! It provides the cryptographic foundation for the CONTINUITY invariant
//! of the PIC model.
//!
//! Key types:
//! - `KeyPair`: Ed25519 key pair for signing
//! - `PublicKey`: Ed25519 public key for verification
//! - `SignedPca`: COSE_Sign1 wrapped PCA
//! - `SignedPoc`: COSE_Sign1 wrapped PoC

use crate::error::{ProvenanceError, Result};
use crate::pca::Pca;
use crate::poc::Poc;
use coset::{
    iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// COSE algorithm identifier for EdDSA (Ed25519)
const EDDSA_ALG: iana::Algorithm = iana::Algorithm::EdDSA;

/// A signed COSE_Sign1 structure
#[derive(Debug, Clone)]
pub struct CoseSigned<T> {
    /// The COSE_Sign1 structure
    cose: CoseSign1,
    /// Phantom type marker
    _marker: std::marker::PhantomData<T>,
}

/// Signed PCA (COSE_Sign1 wrapped)
pub type SignedPca = CoseSigned<Pca>;

/// Signed PoC (COSE_Sign1 wrapped)
pub type SignedPoc = CoseSigned<Poc>;

impl<T> CoseSigned<T> {
    /// Get the raw COSE_Sign1 structure
    pub fn cose(&self) -> &CoseSign1 {
        &self.cose
    }

    /// Get the key ID from the protected header
    pub fn kid(&self) -> Option<String> {
        let kid = &self.cose.protected.header.key_id;
        if kid.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(kid).to_string())
        }
    }

    /// Get the signature bytes
    pub fn signature(&self) -> &[u8] {
        &self.cose.signature
    }

    /// Serialize to CBOR bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.cose.clone().to_vec().map_err(ProvenanceError::from)
    }

    /// Deserialize from CBOR bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let cose = CoseSign1::from_slice(bytes).map_err(ProvenanceError::from)?;
        Ok(Self {
            cose,
            _marker: std::marker::PhantomData,
        })
    }

    /// Get the payload bytes
    pub fn payload(&self) -> Option<&[u8]> {
        self.cose.payload.as_deref()
    }
}

impl SignedPca {
    /// Extract and deserialize the PCA from the payload
    ///
    /// Note: This does NOT verify the signature. Use `PublicKey::verify_pca` for that.
    pub fn extract_pca(&self) -> Result<Pca> {
        let payload = self.cose.payload.as_ref()
            .ok_or(ProvenanceError::MissingField("payload".into()))?;
        Pca::from_bytes(payload)
    }
}

impl SignedPoc {
    /// Extract and deserialize the PoC from the payload
    ///
    /// Note: This does NOT verify the signature. Use `PublicKey::verify_poc` for that.
    pub fn extract_poc(&self) -> Result<Poc> {
        let payload = self.cose.payload.as_ref()
            .ok_or(ProvenanceError::MissingField("payload".into()))?;
        Poc::from_bytes(payload)
    }
}

/// Ed25519 key pair for signing PCAs and PoCs
#[derive(Clone)]
pub struct KeyPair {
    /// Key identifier
    kid: String,
    /// Ed25519 signing key (private)
    signing_key: SigningKey,
    /// Ed25519 verifying key (public)
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("kid", &self.kid)
            .field("verifying_key", &"[redacted]")
            .finish()
    }
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate(kid: impl Into<String>) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Self {
            kid: kid.into(),
            signing_key,
            verifying_key,
        }
    }

    /// Create a key pair from an existing signing key
    pub fn from_signing_key(kid: impl Into<String>, signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            kid: kid.into(),
            signing_key,
            verifying_key,
        }
    }

    /// Create a key pair from raw bytes
    pub fn from_bytes(kid: impl Into<String>, bytes: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(bytes);
        Ok(Self::from_signing_key(kid, signing_key))
    }

    /// Get the key identifier
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            kid: self.kid.clone(),
            verifying_key: self.verifying_key,
        }
    }

    /// Get the raw signing key bytes
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the raw verifying key bytes
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Sign a PCA and wrap in COSE_Sign1
    pub fn sign_pca(&self, pca: &Pca) -> Result<SignedPca> {
        let payload = pca.to_bytes()?;
        let cose = self.sign_cose(&payload)?;
        Ok(CoseSigned {
            cose,
            _marker: std::marker::PhantomData,
        })
    }

    /// Sign a PoC and wrap in COSE_Sign1
    pub fn sign_poc(&self, poc: &Poc) -> Result<SignedPoc> {
        let payload = poc.to_bytes()?;
        let cose = self.sign_cose(&payload)?;
        Ok(CoseSigned {
            cose,
            _marker: std::marker::PhantomData,
        })
    }

    /// Sign arbitrary data and wrap in COSE_Sign1
    fn sign_cose(&self, payload: &[u8]) -> Result<CoseSign1> {
        // Build protected header with algorithm and key ID
        let protected = HeaderBuilder::new()
            .algorithm(EDDSA_ALG)
            .key_id(self.kid.as_bytes().to_vec())
            .build();

        // Build the COSE_Sign1 structure
        let builder = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload.to_vec());

        // Create the signature - try_create_signature returns a Result<CoseSign1Builder>
        let signed_builder = builder.try_create_signature(&[], |data| {
            let signature = self.signing_key.sign(data);
            Ok::<_, ProvenanceError>(signature.to_bytes().to_vec())
        })?;

        // Build the final CoseSign1
        Ok(signed_builder.build())
    }
}

/// Ed25519 public key for verification
#[derive(Clone)]
pub struct PublicKey {
    /// Key identifier
    kid: String,
    /// Ed25519 verifying key
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("kid", &self.kid)
            .finish()
    }
}

impl PublicKey {
    /// Create a public key from raw bytes
    pub fn from_bytes(kid: impl Into<String>, bytes: &[u8; 32]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| ProvenanceError::CryptoError(e.to_string()))?;
        Ok(Self {
            kid: kid.into(),
            verifying_key,
        })
    }

    /// Get the key identifier
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Get the raw verifying key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Verify a signed PCA and extract the payload
    pub fn verify_pca(&self, signed: &SignedPca) -> Result<Pca> {
        self.verify_cose(&signed.cose)?;
        signed.extract_pca()
    }

    /// Verify a signed PoC and extract the payload
    pub fn verify_poc(&self, signed: &SignedPoc) -> Result<Poc> {
        self.verify_cose(&signed.cose)?;
        signed.extract_poc()
    }

    /// Verify a COSE_Sign1 structure
    fn verify_cose(&self, cose: &CoseSign1) -> Result<()> {
        // Verify the key ID matches (if present)
        let kid = &cose.protected.header.key_id;
        if !kid.is_empty() {
            let kid_str = String::from_utf8_lossy(kid);
            if kid_str != self.kid {
                return Err(ProvenanceError::CryptoError(format!(
                    "Key ID mismatch: expected '{}', got '{}'",
                    self.kid, kid_str
                )));
            }
        }

        // Reconstruct the signature input (Sig_structure)
        let sig_structure = cose.tbs_data(&[]);

        // Parse the signature
        let signature_bytes: [u8; 64] = cose.signature.as_slice().try_into()
            .map_err(|_| ProvenanceError::CryptoError(
                "Invalid signature length".into()
            ))?;
        let signature = Signature::from_bytes(&signature_bytes);

        // Verify
        self.verifying_key.verify(&sig_structure, &signature)
            .map_err(|e| ProvenanceError::CryptoError(e.to_string()))
    }
}

/// Serializable public key for storage/transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializablePublicKey {
    /// Key identifier
    pub kid: String,
    /// Base64-encoded public key bytes
    pub key: String,
}

impl From<&PublicKey> for SerializablePublicKey {
    fn from(pk: &PublicKey) -> Self {
        use base64::{engine::general_purpose::STANDARD, Engine};
        Self {
            kid: pk.kid.clone(),
            key: STANDARD.encode(pk.to_bytes()),
        }
    }
}

impl TryFrom<SerializablePublicKey> for PublicKey {
    type Error = ProvenanceError;

    fn try_from(spk: SerializablePublicKey) -> Result<Self> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = STANDARD.decode(&spk.key)
            .map_err(|e| ProvenanceError::CryptoError(e.to_string()))?;
        let bytes: [u8; 32] = bytes.try_into()
            .map_err(|_| ProvenanceError::CryptoError("Invalid key length".into()))?;
        PublicKey::from_bytes(spk.kid, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pca::{ExecutorBinding, PcaBuilder};
    use crate::poc::PocBuilder;
    use crate::types::PrincipalIdentifier;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate("test-key-1");
        assert_eq!(kp.kid(), "test-key-1");

        let pk = kp.public_key();
        assert_eq!(pk.kid(), "test-key-1");
    }

    #[test]
    fn test_sign_and_verify_pca() {
        let kp = KeyPair::generate("trust-plane-1");

        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["read:claims:*".into()])
            .executor(ExecutorBinding::new().with("service", "gateway"))
            .build_pca_0()
            .unwrap();

        // Sign
        let signed = kp.sign_pca(&pca).unwrap();
        assert!(signed.kid().is_some());
        assert_eq!(signed.kid().unwrap(), "trust-plane-1");

        // Verify
        let pk = kp.public_key();
        let verified_pca = pk.verify_pca(&signed).unwrap();

        assert_eq!(verified_pca, pca);
    }

    #[test]
    fn test_sign_and_verify_poc() {
        let kp = KeyPair::generate("executor-1");

        let poc = PocBuilder::new(b"mock-predecessor".to_vec())
            .ops(vec!["read:claims:123".into()])
            .executor(ExecutorBinding::new().with("service", "agent"))
            .build()
            .unwrap();

        // Sign
        let signed = kp.sign_poc(&poc).unwrap();

        // Verify
        let pk = kp.public_key();
        let verified_poc = pk.verify_poc(&signed).unwrap();

        assert_eq!(verified_poc, poc);
    }

    #[test]
    fn test_verification_fails_with_wrong_key() {
        let kp1 = KeyPair::generate("key-1");
        let kp2 = KeyPair::generate("key-2");

        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["read:*".into()])
            .build_pca_0()
            .unwrap();

        // Sign with key 1
        let signed = kp1.sign_pca(&pca).unwrap();

        // Try to verify with key 2 - should fail
        let pk2 = kp2.public_key();
        let result = pk2.verify_pca(&signed);

        assert!(result.is_err());
    }

    #[test]
    fn test_cose_serialization_roundtrip() {
        let kp = KeyPair::generate("test-key");

        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:bob"))
            .ops(vec!["write:data:*".into()])
            .build_pca_0()
            .unwrap();

        let signed = kp.sign_pca(&pca).unwrap();

        // Serialize to bytes
        let bytes = signed.to_bytes().unwrap();

        // Deserialize
        let restored: SignedPca = SignedPca::from_bytes(&bytes).unwrap();

        // Verify still works
        let pk = kp.public_key();
        let verified = pk.verify_pca(&restored).unwrap();

        assert_eq!(verified, pca);
    }

    #[test]
    fn test_extract_kid_from_signed() {
        let kp = KeyPair::generate("my-key-id");

        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["read:*".into()])
            .build_pca_0()
            .unwrap();

        let signed = kp.sign_pca(&pca).unwrap();

        assert_eq!(signed.kid(), Some("my-key-id".to_string()));
    }

    #[test]
    fn test_keypair_from_bytes() {
        let kp1 = KeyPair::generate("key-1");
        let bytes = kp1.signing_key_bytes();

        let kp2 = KeyPair::from_bytes("key-2", &bytes).unwrap();

        // Same signing key, different kid
        assert_eq!(kp2.signing_key_bytes(), bytes);
        assert_eq!(kp2.kid(), "key-2");
    }

    #[test]
    fn test_public_key_serialization() {
        let kp = KeyPair::generate("test");
        let pk = kp.public_key();

        let serializable: SerializablePublicKey = (&pk).into();
        let restored: PublicKey = serializable.try_into().unwrap();

        assert_eq!(restored.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn test_signature_bytes_accessible() {
        let kp = KeyPair::generate("test");

        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["read:*".into()])
            .build_pca_0()
            .unwrap();

        let signed = kp.sign_pca(&pca).unwrap();

        // Ed25519 signatures are 64 bytes
        assert_eq!(signed.signature().len(), 64);
    }
}
