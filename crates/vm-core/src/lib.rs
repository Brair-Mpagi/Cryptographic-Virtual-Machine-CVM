// CVM Core — Public API
//
// Re-exports all core components of the Cryptographic Virtual Machine.

pub mod error;
pub mod memory;
pub mod opcode;
pub mod registers;
pub mod stack;
pub mod value;
pub mod vm;

pub use error::{VmError, VmResult};
pub use memory::Memory;
pub use opcode::Opcode;
pub use registers::RegisterFile;
pub use stack::Stack;
pub use value::Value;
pub use vm::{CryptoDispatcher, SandboxEnforcer, Vm, NoCrypto, NoSandbox, TraceRecord, CVM_MAGIC, HEADER_SIZE};
