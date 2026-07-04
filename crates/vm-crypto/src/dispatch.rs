// CVM Crypto — Opcode Dispatch
//
// Bridges the VM execution loop to the crypto provider.
// Validates stack types, extracts operands, calls provider, pushes results.

use cvm_core::{CryptoDispatcher, Opcode, Stack, Value, VmError, VmResult};
use crate::keystore::{KeyMaterial, KeyStore};
use crate::provider::{CryptoProvider, RustCryptoProvider};

/// Full crypto dispatch implementation for the VM.
pub struct CvmCryptoDispatcher {
    provider: RustCryptoProvider,
    pub keystore: KeyStore,
}

impl CvmCryptoDispatcher {
    pub fn new() -> Self {
        Self {
            provider: RustCryptoProvider::new(),
            keystore: KeyStore::new(),
        }
    }
}

impl Default for CvmCryptoDispatcher {
    fn default() -> Self { Self::new() }
}

impl CryptoDispatcher for CvmCryptoDispatcher {
    fn dispatch(&mut self, opcode: Opcode, stack: &mut Stack) -> VmResult<()> {
        match opcode {
            Opcode::Sha256 => {
                let data = stack.pop()?.into_bytes()?;
                let hash = self.provider.sha256(&data);
                stack.push(Value::Bytes(hash))
            }

            Opcode::Sha3_256 => {
                let data = stack.pop()?.into_bytes()?;
                let hash = self.provider.sha3_256(&data);
                stack.push(Value::Bytes(hash))
            }

            Opcode::Hmac => {
                let data = stack.pop()?.into_bytes()?;
                let key_handle = stack.pop()?.as_key_handle()?;
                let key_mat = self.keystore.get(key_handle)?;
                match key_mat {
                    KeyMaterial::Symmetric(key) => {
                        let mac = self.provider.hmac_sha256(key, &data);
                        stack.push(Value::Bytes(mac))
                    }
                    _ => Err(VmError::TypeMismatch {
                        expected: "Symmetric key",
                        got: key_mat.key_type().to_string(),
                    }),
                }
            }

            Opcode::AesEncrypt => {
                let data = stack.pop()?.into_bytes()?;
                let nonce = stack.pop()?.into_bytes()?;
                let key_handle = stack.pop()?.as_key_handle()?;
                let key_mat = self.keystore.get(key_handle)?;
                match key_mat {
                    KeyMaterial::Symmetric(key) => {
                        let ct = self.provider.aes_gcm_encrypt(key, &nonce, &data)?;
                        stack.push(Value::Bytes(ct))
                    }
                    _ => Err(VmError::TypeMismatch {
                        expected: "Symmetric key",
                        got: key_mat.key_type().to_string(),
                    }),
                }
            }

            Opcode::AesDecrypt => {
                let ct = stack.pop()?.into_bytes()?;
                let nonce = stack.pop()?.into_bytes()?;
                let key_handle = stack.pop()?.as_key_handle()?;
                let key_mat = self.keystore.get(key_handle)?;
                match key_mat {
                    KeyMaterial::Symmetric(key) => {
                        let pt = self.provider.aes_gcm_decrypt(key, &nonce, &ct)?;
                        stack.push(Value::Bytes(pt))
                    }
                    _ => Err(VmError::TypeMismatch {
                        expected: "Symmetric key",
                        got: key_mat.key_type().to_string(),
                    }),
                }
            }

            Opcode::RsaSign => {
                let data = stack.pop()?.into_bytes()?;
                let key_handle = stack.pop()?.as_key_handle()?;
                let key_mat = self.keystore.get(key_handle)?;
                match key_mat {
                    KeyMaterial::Rsa { private, .. } => {
                        let sig = self.provider.rsa_sign(private, &data)?;
                        stack.push(Value::Bytes(sig))
                    }
                    _ => Err(VmError::TypeMismatch {
                        expected: "RSA key",
                        got: key_mat.key_type().to_string(),
                    }),
                }
            }

            Opcode::RsaVerify => {
                let sig = stack.pop()?.into_bytes()?;
                let data = stack.pop()?.into_bytes()?;
                let key_handle = stack.pop()?.as_key_handle()?;
                let key_mat = self.keystore.get(key_handle)?;
                match key_mat {
                    KeyMaterial::Rsa { public, .. } => {
                        let valid = self.provider.rsa_verify(public, &data, &sig)?;
                        stack.push(Value::Bool(valid))
                    }
                    _ => Err(VmError::TypeMismatch {
                        expected: "RSA key",
                        got: key_mat.key_type().to_string(),
                    }),
                }
            }

            Opcode::EcdsaSign => {
                let data = stack.pop()?.into_bytes()?;
                let key_handle = stack.pop()?.as_key_handle()?;
                let key_mat = self.keystore.get(key_handle)?;
                match key_mat {
                    KeyMaterial::Ecdsa { private, .. } => {
                        let sig = self.provider.ecdsa_sign(private, &data)?;
                        stack.push(Value::Bytes(sig))
                    }
                    _ => Err(VmError::TypeMismatch {
                        expected: "ECDSA key",
                        got: key_mat.key_type().to_string(),
                    }),
                }
            }

            Opcode::EcdsaVerify => {
                let sig = stack.pop()?.into_bytes()?;
                let data = stack.pop()?.into_bytes()?;
                let key_handle = stack.pop()?.as_key_handle()?;
                let key_mat = self.keystore.get(key_handle)?;
                match key_mat {
                    KeyMaterial::Ecdsa { public, .. } => {
                        let valid = self.provider.ecdsa_verify(public, &data, &sig)?;
                        stack.push(Value::Bool(valid))
                    }
                    _ => Err(VmError::TypeMismatch {
                        expected: "ECDSA key",
                        got: key_mat.key_type().to_string(),
                    }),
                }
            }

            Opcode::RandBytes => {
                let len = stack.pop()?.as_int()? as usize;
                let bytes = self.provider.rand_bytes(len);
                stack.push(Value::Bytes(bytes))
            }

            Opcode::GenSymKey => {
                let handle = self.keystore.generate_symmetric(&self.provider);
                stack.push(Value::KeyHandle(handle))
            }

            Opcode::GenRsaKey => {
                let handle = self.keystore.generate_rsa(&self.provider)?;
                stack.push(Value::KeyHandle(handle))
            }

            Opcode::GenEcKey => {
                let handle = self.keystore.generate_ecdsa(&self.provider)?;
                stack.push(Value::KeyHandle(handle))
            }

            _ => Err(VmError::CryptoError(format!("unhandled crypto opcode: {}", opcode))),
        }
    }
}
