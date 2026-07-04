// CVM Crypto — Provider trait and RustCrypto implementation

use cvm_core::error::{VmError, VmResult};

/// Abstraction over all cryptographic operations.
/// Implementations wrap vetted libraries — NEVER hand-roll crypto.
pub trait CryptoProvider {
    fn sha256(&self, data: &[u8]) -> Vec<u8>;
    fn sha3_256(&self, data: &[u8]) -> Vec<u8>;
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Vec<u8>;
    fn aes_gcm_encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> VmResult<Vec<u8>>;
    fn aes_gcm_decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> VmResult<Vec<u8>>;
    fn rsa_sign(&self, private_key_der: &[u8], data: &[u8]) -> VmResult<Vec<u8>>;
    fn rsa_verify(&self, public_key_der: &[u8], data: &[u8], signature: &[u8]) -> VmResult<bool>;
    fn ecdsa_sign(&self, private_key: &[u8], data: &[u8]) -> VmResult<Vec<u8>>;
    fn ecdsa_verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> VmResult<bool>;
    fn rand_bytes(&self, len: usize) -> Vec<u8>;
    fn generate_aes_key(&self) -> Vec<u8>;
    fn generate_rsa_keypair(&self) -> VmResult<(Vec<u8>, Vec<u8>)>; // (private, public)
    fn generate_ecdsa_keypair(&self) -> VmResult<(Vec<u8>, Vec<u8>)>;
}

/// RustCrypto-backed implementation.
pub struct RustCryptoProvider;

impl RustCryptoProvider {
    pub fn new() -> Self { Self }
}

impl Default for RustCryptoProvider {
    fn default() -> Self { Self::new() }
}

impl CryptoProvider for RustCryptoProvider {
    fn sha256(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn sha3_256(&self, data: &[u8]) -> Vec<u8> {
        use sha3::Digest;
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn aes_gcm_encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> VmResult<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
        if key.len() != 32 {
            return Err(VmError::CryptoError("AES-256-GCM requires 32-byte key".into()));
        }
        if nonce.len() != 12 {
            return Err(VmError::CryptoError("AES-GCM requires 12-byte nonce".into()));
        }
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| VmError::CryptoError(format!("AES key error: {}", e)))?;
        let nonce = Nonce::from_slice(nonce);
        cipher.encrypt(nonce, plaintext)
            .map_err(|e| VmError::CryptoError(format!("AES encrypt failed: {}", e)))
    }

    fn aes_gcm_decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> VmResult<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
        if key.len() != 32 {
            return Err(VmError::CryptoError("AES-256-GCM requires 32-byte key".into()));
        }
        if nonce.len() != 12 {
            return Err(VmError::CryptoError("AES-GCM requires 12-byte nonce".into()));
        }
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| VmError::CryptoError(format!("AES key error: {}", e)))?;
        let nonce = Nonce::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| VmError::CryptoError(format!("AES decrypt failed: {}", e)))
    }

    fn rsa_sign(&self, private_key_der: &[u8], data: &[u8]) -> VmResult<Vec<u8>> {
        use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
        use rsa::signature::{SignatureEncoding, RandomizedSigner};
        use rsa::pss::SigningKey;
        let key = RsaPrivateKey::from_pkcs8_der(private_key_der)
            .map_err(|e| VmError::CryptoError(format!("RSA key decode: {}", e)))?;
        let signing_key = SigningKey::<sha2::Sha256>::new(key);
        let mut rng = rand::thread_rng();
        let signature = signing_key.sign_with_rng(&mut rng, data);
        Ok(signature.to_bytes().to_vec())
    }

    fn rsa_verify(&self, public_key_der: &[u8], data: &[u8], signature: &[u8]) -> VmResult<bool> {
        use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
        use rsa::signature::Verifier;
        use rsa::pss::{VerifyingKey, Signature};
        let key = RsaPublicKey::from_public_key_der(public_key_der)
            .map_err(|e| VmError::CryptoError(format!("RSA pub key decode: {}", e)))?;
        let verifying_key = VerifyingKey::<sha2::Sha256>::new(key);
        let sig = Signature::try_from(signature)
            .map_err(|e| VmError::CryptoError(format!("RSA sig decode: {}", e)))?;
        Ok(verifying_key.verify(data, &sig).is_ok())
    }

    fn ecdsa_sign(&self, private_key: &[u8], data: &[u8]) -> VmResult<Vec<u8>> {
        use p256::ecdsa::{SigningKey, signature::Signer, Signature};
        let key = SigningKey::from_slice(private_key)
            .map_err(|e| VmError::CryptoError(format!("ECDSA key decode: {}", e)))?;
        let signature: Signature = key.sign(data);
        Ok(signature.to_der().to_bytes().to_vec())
    }

    fn ecdsa_verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> VmResult<bool> {
        use p256::ecdsa::{VerifyingKey, DerSignature, signature::Verifier};
        let key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| VmError::CryptoError(format!("ECDSA pub key decode: {}", e)))?;
        let sig = DerSignature::from_bytes(signature)
            .map_err(|e| VmError::CryptoError(format!("ECDSA sig decode: {}", e)))?;
        Ok(key.verify(data, &sig).is_ok())
    }

    fn rand_bytes(&self, len: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut buf = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    fn generate_aes_key(&self) -> Vec<u8> {
        self.rand_bytes(32)
    }

    fn generate_rsa_keypair(&self) -> VmResult<(Vec<u8>, Vec<u8>)> {
        use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey, pkcs8::EncodePublicKey};
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| VmError::CryptoError(format!("RSA keygen: {}", e)))?;
        let public_key = private_key.to_public_key();
        let priv_der = private_key.to_pkcs8_der()
            .map_err(|e| VmError::CryptoError(format!("RSA priv encode: {}", e)))?;
        let pub_der = public_key.to_public_key_der()
            .map_err(|e| VmError::CryptoError(format!("RSA pub encode: {}", e)))?;
        Ok((priv_der.as_bytes().to_vec(), pub_der.as_ref().to_vec()))
    }

    fn generate_ecdsa_keypair(&self) -> VmResult<(Vec<u8>, Vec<u8>)> {
        use p256::ecdsa::SigningKey;
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        Ok((
            signing_key.to_bytes().to_vec(),
            verifying_key.to_sec1_bytes().to_vec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let p = RustCryptoProvider::new();
        let hash = p.sha256(b"hello");
        assert_eq!(hash.len(), 32);
        // Known SHA-256 of "hello"
        assert_eq!(hex::encode(&hash), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_aes_roundtrip() {
        let p = RustCryptoProvider::new();
        let key = p.generate_aes_key();
        let nonce = p.rand_bytes(12);
        let plaintext = b"secret data";
        let ct = p.aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        let pt = p.aes_gcm_decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_ecdsa_roundtrip() {
        let p = RustCryptoProvider::new();
        let (priv_key, pub_key) = p.generate_ecdsa_keypair().unwrap();
        let data = b"test message";
        let sig = p.ecdsa_sign(&priv_key, data).unwrap();
        let valid = p.ecdsa_verify(&pub_key, data, &sig).unwrap();
        assert!(valid);
        // Tampered data should fail
        let invalid = p.ecdsa_verify(&pub_key, b"wrong", &sig).unwrap();
        assert!(!invalid);
    }
}
