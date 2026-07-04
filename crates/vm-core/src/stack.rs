// CVM Core — Operand Stack

use crate::error::{VmError, VmResult};
use crate::value::Value;

const DEFAULT_STACK_LIMIT: usize = 65536;

/// The operand stack for the CVM.
pub struct Stack {
    data: Vec<Value>,
    limit: usize,
}

impl Stack {
    pub fn new() -> Self {
        Self { data: Vec::with_capacity(256), limit: DEFAULT_STACK_LIMIT }
    }

    pub fn with_limit(limit: usize) -> Self {
        Self { data: Vec::with_capacity(256), limit }
    }

    pub fn push(&mut self, value: Value) -> VmResult<()> {
        if self.data.len() >= self.limit {
            return Err(VmError::StackOverflow { size: self.data.len(), limit: self.limit });
        }
        self.data.push(value);
        Ok(())
    }

    pub fn pop(&mut self) -> VmResult<Value> {
        self.data.pop().ok_or(VmError::StackUnderflow { operation: "pop", depth: 0 })
    }

    pub fn peek(&self) -> VmResult<&Value> {
        self.data.last().ok_or(VmError::StackUnderflow { operation: "peek", depth: 0 })
    }

    pub fn dup(&mut self) -> VmResult<()> {
        let val = self.peek()?.clone();
        self.push(val)
    }

    pub fn swap(&mut self) -> VmResult<()> {
        let len = self.data.len();
        if len < 2 {
            return Err(VmError::StackUnderflow { operation: "swap", depth: len });
        }
        self.data.swap(len - 1, len - 2);
        Ok(())
    }

    pub fn len(&self) -> usize { self.data.len() }
    pub fn is_empty(&self) -> bool { self.data.is_empty() }

    /// Get a snapshot of the stack for debugging.
    pub fn dump(&self) -> Vec<String> {
        self.data.iter().enumerate().map(|(i, v)| format!("[{}] {}", i, v)).collect()
    }

    pub fn clear(&mut self) { self.data.clear(); }
}

impl Default for Stack {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_pop() {
        let mut s = Stack::new();
        s.push(Value::Int(42)).unwrap();
        s.push(Value::Bool(true)).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.pop().unwrap(), Value::Bool(true));
        assert_eq!(s.pop().unwrap(), Value::Int(42));
        assert!(s.pop().is_err());
    }

    #[test]
    fn test_dup_swap() {
        let mut s = Stack::new();
        s.push(Value::Int(1)).unwrap();
        s.push(Value::Int(2)).unwrap();
        s.dup().unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!(s.pop().unwrap(), Value::Int(2));
        s.swap().unwrap();
        assert_eq!(s.pop().unwrap(), Value::Int(1));
        assert_eq!(s.pop().unwrap(), Value::Int(2));
    }

    #[test]
    fn test_overflow() {
        let mut s = Stack::with_limit(2);
        s.push(Value::Int(1)).unwrap();
        s.push(Value::Int(2)).unwrap();
        assert!(s.push(Value::Int(3)).is_err());
    }
}
