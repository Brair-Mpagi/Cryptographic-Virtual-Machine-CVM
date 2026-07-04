// CVM Sandbox — Execution policy (instruction whitelist/blacklist)

use cvm_core::{Opcode, VmError, VmResult, SandboxEnforcer};
use crate::gas::GasCounter;
use std::collections::HashSet;

/// Policy mode for instruction filtering.
#[derive(Debug, Clone)]
pub enum FilterMode {
    /// All instructions allowed (default).
    AllowAll,
    /// Only listed instructions are allowed.
    Whitelist(HashSet<u8>),
    /// Listed instructions are denied.
    Blacklist(HashSet<u8>),
}

/// Execution profile combining gas limits and instruction policies.
pub struct ExecutionPolicy {
    gas: GasCounter,
    filter: FilterMode,
}

impl ExecutionPolicy {
    /// Create a policy with a gas limit and no instruction restrictions.
    pub fn with_gas_limit(limit: u64) -> Self {
        Self {
            gas: GasCounter::new(limit),
            filter: FilterMode::AllowAll,
        }
    }

    /// No restrictions at all.
    pub fn unrestricted() -> Self {
        Self {
            gas: GasCounter::unlimited(),
            filter: FilterMode::AllowAll,
        }
    }

    /// Set a whitelist of allowed opcodes.
    pub fn with_whitelist(mut self, opcodes: Vec<Opcode>) -> Self {
        self.filter = FilterMode::Whitelist(
            opcodes.into_iter().map(|op| op.to_byte()).collect()
        );
        self
    }

    /// Set a blacklist of denied opcodes.
    pub fn with_blacklist(mut self, opcodes: Vec<Opcode>) -> Self {
        self.filter = FilterMode::Blacklist(
            opcodes.into_iter().map(|op| op.to_byte()).collect()
        );
        self
    }

    /// Create a "no crypto" policy — blocks all crypto opcodes.
    pub fn no_crypto(gas_limit: u64) -> Self {
        let crypto_ops = vec![
            Opcode::Sha256, Opcode::Sha3_256, Opcode::Hmac,
            Opcode::AesEncrypt, Opcode::AesDecrypt,
            Opcode::RsaSign, Opcode::RsaVerify,
            Opcode::EcdsaSign, Opcode::EcdsaVerify,
            Opcode::RandBytes, Opcode::GenSymKey, Opcode::GenRsaKey, Opcode::GenEcKey,
        ];
        Self::with_gas_limit(gas_limit).with_blacklist(crypto_ops)
    }

    pub fn gas_consumed(&self) -> u64 { self.gas.consumed() }
    pub fn gas_remaining(&self) -> u64 { self.gas.remaining() }
}

impl SandboxEnforcer for ExecutionPolicy {
    fn pre_execute(&mut self, opcode: Opcode) -> VmResult<()> {
        // Check instruction filter
        let byte = opcode.to_byte();
        match &self.filter {
            FilterMode::AllowAll => {}
            FilterMode::Whitelist(allowed) => {
                if !allowed.contains(&byte) {
                    return Err(VmError::InstructionDenied {
                        opcode: opcode.mnemonic().to_string(),
                    });
                }
            }
            FilterMode::Blacklist(denied) => {
                if denied.contains(&byte) {
                    return Err(VmError::InstructionDenied {
                        opcode: opcode.mnemonic().to_string(),
                    });
                }
            }
        }

        // Check gas
        self.gas.consume(opcode)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_enforcement() {
        let mut policy = ExecutionPolicy::with_gas_limit(3);
        policy.pre_execute(Opcode::Nop).unwrap();
        policy.pre_execute(Opcode::Nop).unwrap();
        policy.pre_execute(Opcode::Nop).unwrap();
        assert!(policy.pre_execute(Opcode::Nop).is_err());
    }

    #[test]
    fn test_blacklist() {
        let mut policy = ExecutionPolicy::no_crypto(1000);
        assert!(policy.pre_execute(Opcode::Nop).is_ok());
        assert!(policy.pre_execute(Opcode::Sha256).is_err());
    }

    #[test]
    fn test_whitelist() {
        let mut policy = ExecutionPolicy::with_gas_limit(1000)
            .with_whitelist(vec![Opcode::PushInt, Opcode::Halt, Opcode::Add]);
        assert!(policy.pre_execute(Opcode::PushInt).is_ok());
        assert!(policy.pre_execute(Opcode::Halt).is_ok());
        assert!(policy.pre_execute(Opcode::Sha256).is_err());
    }
}
