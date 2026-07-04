// CVM Sandbox — Gas/step counter

use cvm_core::{Opcode, VmError, VmResult};

/// Tracks and enforces gas/step limits during VM execution.
pub struct GasCounter {
    limit: u64,
    consumed: u64,
}

impl GasCounter {
    pub fn new(limit: u64) -> Self {
        Self { limit, consumed: 0 }
    }

    /// Unlimited gas (effectively no limit).
    pub fn unlimited() -> Self {
        Self { limit: u64::MAX, consumed: 0 }
    }

    /// Consume gas for an opcode. Returns error if limit exceeded.
    pub fn consume(&mut self, opcode: Opcode) -> VmResult<()> {
        let cost = opcode.gas_cost();
        self.consumed += cost;
        if self.consumed > self.limit {
            Err(VmError::GasExhausted {
                executed: self.consumed,
                limit: self.limit,
            })
        } else {
            Ok(())
        }
    }

    pub fn consumed(&self) -> u64 { self.consumed }
    pub fn limit(&self) -> u64 { self.limit }
    pub fn remaining(&self) -> u64 { self.limit.saturating_sub(self.consumed) }

    pub fn reset(&mut self) {
        self.consumed = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_limit() {
        let mut gc = GasCounter::new(5);
        gc.consume(Opcode::Nop).unwrap(); // cost 1
        gc.consume(Opcode::Nop).unwrap(); // cost 1
        gc.consume(Opcode::Nop).unwrap(); // cost 1
        gc.consume(Opcode::Nop).unwrap(); // cost 1
        gc.consume(Opcode::Nop).unwrap(); // cost 1, total=5
        assert!(gc.consume(Opcode::Nop).is_err()); // over limit
    }

    #[test]
    fn test_crypto_costs_more() {
        let mut gc = GasCounter::new(5);
        // SHA256 costs 10 — should exceed limit of 5
        assert!(gc.consume(Opcode::Sha256).is_err());
    }
}
