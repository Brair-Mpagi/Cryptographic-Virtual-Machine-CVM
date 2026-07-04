// CVM Core — Error types
//
// All error conditions that can occur during VM execution.
// Uses thiserror for ergonomic error derivation.

/// Errors that can occur during CVM execution.
#[derive(Debug, Clone, thiserror::Error)]
pub enum VmError {
    /// Stack underflow: attempted to pop/peek from an empty stack.
    #[error("E01 StackUnderflow: attempted to {operation} on stack with {depth} elements")]
    StackUnderflow {
        operation: &'static str,
        depth: usize,
    },

    /// Stack overflow: stack exceeded maximum capacity.
    #[error("E02 StackOverflow: stack size {size} exceeds limit {limit}")]
    StackOverflow { size: usize, limit: usize },

    /// Invalid opcode byte encountered during decode.
    #[error("E03 InvalidOpcode: unknown opcode byte 0x{0:02X}")]
    InvalidOpcode(u8),

    /// Type mismatch: instruction received wrong value type.
    #[error("E04 TypeMismatch: expected {expected}, got {got}")]
    TypeMismatch {
        expected: &'static str,
        got: String,
    },

    /// Out of bounds memory access.
    #[error("E05 OutOfBounds: address 0x{address:08X}, size {size}")]
    OutOfBounds { address: u32, size: usize },

    /// Division by zero.
    #[error("E06 DivisionByZero")]
    DivisionByZero,

    /// Gas/step limit exhausted.
    #[error("E07 GasExhausted: executed {executed} steps, limit was {limit}")]
    GasExhausted { executed: u64, limit: u64 },

    /// Cryptographic operation failed.
    #[error("E08 CryptoError: {0}")]
    CryptoError(String),

    /// Invalid key handle — not found in the key store.
    #[error("E09 InvalidKeyHandle: handle {0} not found in key store")]
    InvalidKeyHandle(u32),

    /// Invalid register index (must be 0–7).
    #[error("E10 InvalidRegister: register R{0} out of range (valid: R0–R7)")]
    InvalidRegister(u8),

    /// Invalid bytecode file (bad magic, version, or truncated).
    #[error("E11 InvalidBytecode: {0}")]
    InvalidBytecode(String),

    /// Program reached HALT instruction (normal termination).
    #[error("HaltReached: program terminated normally")]
    HaltReached,

    /// Program counter went out of bounds.
    #[error("ProgramCounterOutOfBounds: PC={pc}, code size={code_size}")]
    ProgramCounterOutOfBounds { pc: usize, code_size: usize },

    /// Call stack underflow on RET.
    #[error("CallStackUnderflow: RET without matching CALL")]
    CallStackUnderflow,

    /// Instruction not permitted by sandbox policy.
    #[error("InstructionDenied: opcode {opcode} not permitted by execution policy")]
    InstructionDenied { opcode: String },

    /// Memory quota exceeded.
    #[error("MemoryQuotaExceeded: attempted to allocate {requested} bytes, {used}/{quota} used")]
    MemoryQuotaExceeded {
        requested: usize,
        used: usize,
        quota: usize,
    },
}

/// Result type alias for VM operations.
pub type VmResult<T> = Result<T, VmError>;

impl VmError {
    /// Returns the error code string (E01, E02, etc.).
    pub fn code(&self) -> &'static str {
        match self {
            VmError::StackUnderflow { .. } => "E01",
            VmError::StackOverflow { .. } => "E02",
            VmError::InvalidOpcode(_) => "E03",
            VmError::TypeMismatch { .. } => "E04",
            VmError::OutOfBounds { .. } => "E05",
            VmError::DivisionByZero => "E06",
            VmError::GasExhausted { .. } => "E07",
            VmError::CryptoError(_) => "E08",
            VmError::InvalidKeyHandle(_) => "E09",
            VmError::InvalidRegister(_) => "E10",
            VmError::InvalidBytecode(_) => "E11",
            VmError::HaltReached => "OK",
            VmError::ProgramCounterOutOfBounds { .. } => "E12",
            VmError::CallStackUnderflow => "E13",
            VmError::InstructionDenied { .. } => "E14",
            VmError::MemoryQuotaExceeded { .. } => "E15",
        }
    }

    /// Returns true if this error represents normal program termination.
    pub fn is_halt(&self) -> bool {
        matches!(self, VmError::HaltReached)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        let err = VmError::StackUnderflow {
            operation: "pop",
            depth: 0,
        };
        assert_eq!(err.code(), "E01");
        assert!(!err.is_halt());

        let halt = VmError::HaltReached;
        assert!(halt.is_halt());
        assert_eq!(halt.code(), "OK");
    }

    #[test]
    fn test_error_display() {
        let err = VmError::InvalidOpcode(0xFF);
        assert!(format!("{}", err).contains("0xFF"));
    }
}
