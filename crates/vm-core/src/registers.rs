// CVM Core — Register File (R0–R7)

use crate::error::{VmError, VmResult};
use crate::value::Value;

const NUM_REGISTERS: usize = 8;

/// Eight general-purpose registers (R0–R7) for scratch values.
pub struct RegisterFile {
    regs: [Option<Value>; NUM_REGISTERS],
}

impl RegisterFile {
    pub fn new() -> Self {
        Self { regs: Default::default() }
    }

    pub fn get(&self, index: u8) -> VmResult<&Value> {
        if index as usize >= NUM_REGISTERS {
            return Err(VmError::InvalidRegister(index));
        }
        self.regs[index as usize].as_ref().ok_or(VmError::TypeMismatch {
            expected: "initialized register",
            got: format!("uninitialized R{}", index),
        })
    }

    pub fn set(&mut self, index: u8, value: Value) -> VmResult<()> {
        if index as usize >= NUM_REGISTERS {
            return Err(VmError::InvalidRegister(index));
        }
        self.regs[index as usize] = Some(value);
        Ok(())
    }

    /// Get a snapshot for debugging.
    pub fn dump(&self) -> Vec<String> {
        self.regs.iter().enumerate().map(|(i, v)| {
            match v {
                Some(val) => format!("R{}: {}", i, val),
                None => format!("R{}: <unset>", i),
            }
        }).collect()
    }

    pub fn clear(&mut self) {
        self.regs = Default::default();
    }
}

impl Default for RegisterFile {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_get() {
        let mut rf = RegisterFile::new();
        rf.set(0, Value::Int(42)).unwrap();
        assert_eq!(rf.get(0).unwrap(), &Value::Int(42));
    }

    #[test]
    fn test_invalid_register() {
        let rf = RegisterFile::new();
        assert!(rf.get(8).is_err());
    }

    #[test]
    fn test_uninitialized() {
        let rf = RegisterFile::new();
        assert!(rf.get(0).is_err());
    }
}
