// CVM Core — Typed value system
//
// Values on the stack and in registers carry type tags.
// KeyHandle values are opaque — raw key material never touches the stack.

use crate::error::{VmError, VmResult};
use std::fmt;

/// A typed value in the CVM.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Signed 64-bit integer.
    Int(i64),
    /// Variable-length byte array.
    Bytes(Vec<u8>),
    /// Boolean.
    Bool(bool),
    /// Opaque key handle — an index into the key store.
    /// Raw key material is NEVER exposed on the stack.
    KeyHandle(u32),
}

impl Value {
    /// Get the type name for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Int(_) => "Int",
            Value::Bytes(_) => "Bytes",
            Value::Bool(_) => "Bool",
            Value::KeyHandle(_) => "KeyHandle",
        }
    }

    /// Extract as i64, or return TypeMismatch error.
    pub fn as_int(&self) -> VmResult<i64> {
        match self {
            Value::Int(v) => Ok(*v),
            other => Err(VmError::TypeMismatch {
                expected: "Int",
                got: other.type_name().to_string(),
            }),
        }
    }

    /// Extract as byte slice, or return TypeMismatch error.
    pub fn as_bytes(&self) -> VmResult<&[u8]> {
        match self {
            Value::Bytes(v) => Ok(v),
            other => Err(VmError::TypeMismatch {
                expected: "Bytes",
                got: other.type_name().to_string(),
            }),
        }
    }

    /// Extract as owned bytes, or return TypeMismatch error.
    pub fn into_bytes(self) -> VmResult<Vec<u8>> {
        match self {
            Value::Bytes(v) => Ok(v),
            other => Err(VmError::TypeMismatch {
                expected: "Bytes",
                got: other.type_name().to_string(),
            }),
        }
    }

    /// Extract as bool, or return TypeMismatch error.
    pub fn as_bool(&self) -> VmResult<bool> {
        match self {
            Value::Bool(v) => Ok(*v),
            other => Err(VmError::TypeMismatch {
                expected: "Bool",
                got: other.type_name().to_string(),
            }),
        }
    }

    /// Extract as key handle index, or return TypeMismatch error.
    pub fn as_key_handle(&self) -> VmResult<u32> {
        match self {
            Value::KeyHandle(h) => Ok(*h),
            other => Err(VmError::TypeMismatch {
                expected: "KeyHandle",
                got: other.type_name().to_string(),
            }),
        }
    }

    /// Check if this value is "truthy" for conditional jumps.
    /// Int(0) and Bool(false) are falsy; everything else is truthy.
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Int(v) => *v != 0,
            Value::Bool(v) => *v,
            Value::Bytes(v) => !v.is_empty(),
            Value::KeyHandle(_) => true,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(v) => write!(f, "{}", v),
            Value::Bytes(v) => {
                if v.len() <= 32 {
                    write!(f, "0x{}", hex_encode(v))
                } else {
                    write!(f, "0x{}...({} bytes)", hex_encode(&v[..16]), v.len())
                }
            }
            Value::Bool(v) => write!(f, "{}", v),
            Value::KeyHandle(h) => write!(f, "KeyHandle({})", h),
        }
    }
}

/// Simple hex encoding without external dependency in core.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_extraction() {
        assert_eq!(Value::Int(42).as_int().unwrap(), 42);
        assert!(Value::Int(42).as_bytes().is_err());
        assert_eq!(Value::Bool(true).as_bool().unwrap(), true);
        assert_eq!(Value::KeyHandle(5).as_key_handle().unwrap(), 5);
    }

    #[test]
    fn test_truthiness() {
        assert!(Value::Int(1).is_truthy());
        assert!(!Value::Int(0).is_truthy());
        assert!(Value::Bool(true).is_truthy());
        assert!(!Value::Bool(false).is_truthy());
        assert!(!Value::Bytes(vec![]).is_truthy());
        assert!(Value::Bytes(vec![1]).is_truthy());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Value::Int(42)), "42");
        assert_eq!(format!("{}", Value::Bool(true)), "true");
        assert!(format!("{}", Value::Bytes(vec![0xDE, 0xAD])).contains("dead"));
    }
}
