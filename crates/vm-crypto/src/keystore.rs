// CVM Crypto — Key Store
//
// Maps opaque KeyHandle values to actual key material.
// Keys are NEVER exposed on the VM stack — only handles.

use cvm_core::error::{VmError, VmResult};
use crate::provider::CryptoProvider;
use std::collections::HashMap;

/// Types of keys stored in the key store.
#[derive(Debug, Clone)]
pub enum KeyMaterial {
    /// AES-256 symmetric key (32 bytes)
    Symmetric(Vec<u8>),
    /// RSA keypair: (private_key_der, public_key_der)
    Rsa { private: Vec<u8>, public: Vec<u8> },
    /// ECDSA-P256 keypair: (private_key_bytes, public_key_sec1)
    Ecdsa { private: Vec<u8>, public: Vec<u8> },
}

impl KeyMaterial {
    pub fn key_type(&self) -> &'static str {
        match self {
            KeyMaterial::Symmetric(_) => "Symmetric",
            KeyMaterial::Rsa { .. } => "RSA",
            KeyMaterial::Ecdsa { .. } => "ECDSA",
        }
    }
}

/// Secure key store — maps handles to key material.
pub struct KeyStore {
    keys: HashMap<u32, KeyMaterial>,
    next_handle: u32,
}

impl KeyStore {
    pub fn new() -> Self {
        Self { keys: HashMap::new(), next_handle: 1 }
    }

    /// Insert key material, return the opaque handle.
    fn insert(&mut self, material: KeyMaterial) -> u32 {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.keys.insert(handle, material);
        handle
    }

    /// Get key material by handle.
    pub fn get(&self, handle: u32) -> VmResult<&KeyMaterial> {
        self.keys.get(&handle).ok_or(VmError::InvalidKeyHandle(handle))
    }

    /// Generate and store a new AES-256 key.
    pub fn generate_symmetric<P: CryptoProvider>(&mut self, provider: &P) -> u32 {
        let key = provider.generate_aes_key();
        self.insert(KeyMaterial::Symmetric(key))
    }

    /// Generate and store a new RSA-2048 keypair.
    pub fn generate_rsa<P: CryptoProvider>(&mut self, provider: &P) -> VmResult<u32> {
        let (private, public) = provider.generate_rsa_keypair()?;
        Ok(self.insert(KeyMaterial::Rsa { private, public }))
    }

    /// Generate and store a new ECDSA-P256 keypair.
    pub fn generate_ecdsa<P: CryptoProvider>(&mut self, provider: &P) -> VmResult<u32> {
        let (private, public) = provider.generate_ecdsa_keypair()?;
        Ok(self.insert(KeyMaterial::Ecdsa { private, public }))
    }

    pub fn count(&self) -> usize { self.keys.len() }
}

impl Default for KeyStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::RustCryptoProvider;

    #[test]
    fn test_symmetric_key() {
        let provider = RustCryptoProvider::new();
        let mut store = KeyStore::new();
        let h = store.generate_symmetric(&provider);
        assert!(h > 0);
        let key = store.get(h).unwrap();
        assert!(matches!(key, KeyMaterial::Symmetric(k) if k.len() == 32));
    }

    #[test]
    fn test_invalid_handle() {
        let store = KeyStore::new();
        assert!(store.get(999).is_err());
    }

    #[test]
    fn test_ecdsa_key() {
        let provider = RustCryptoProvider::new();
        let mut store = KeyStore::new();
        let h = store.generate_ecdsa(&provider).unwrap();
        assert!(matches!(store.get(h).unwrap(), KeyMaterial::Ecdsa { .. }));
    }
}
