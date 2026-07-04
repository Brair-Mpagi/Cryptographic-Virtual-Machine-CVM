// CVM Core — Virtual Machine (fetch-decode-execute loop)

use crate::error::{VmError, VmResult};
use crate::memory::Memory;
use crate::opcode::Opcode;
use crate::registers::RegisterFile;
use crate::stack::Stack;
use crate::value::Value;

/// Magic bytes for CVM bytecode files: "CVM\0"
pub const CVM_MAGIC: [u8; 4] = [0x43, 0x56, 0x4D, 0x00];
/// Header size in bytes
pub const HEADER_SIZE: usize = 12;

/// Callback trait for crypto operations — implemented by vm-crypto.
pub trait CryptoDispatcher {
    fn dispatch(&mut self, opcode: Opcode, stack: &mut Stack) -> VmResult<()>;
}

/// Callback trait for sandbox enforcement — implemented by vm-sandbox.
pub trait SandboxEnforcer {
    /// Called before each instruction. Returns Err if denied.
    fn pre_execute(&mut self, opcode: Opcode) -> VmResult<()>;
}

/// No-op crypto dispatcher (crypto opcodes will trap).
pub struct NoCrypto;
impl CryptoDispatcher for NoCrypto {
    fn dispatch(&mut self, opcode: Opcode, _stack: &mut Stack) -> VmResult<()> {
        Err(VmError::CryptoError(format!("{} requires crypto provider", opcode)))
    }
}

/// No-op sandbox (all instructions allowed, no gas limit).
pub struct NoSandbox;
impl SandboxEnforcer for NoSandbox {
    fn pre_execute(&mut self, _opcode: Opcode) -> VmResult<()> { Ok(()) }
}

/// Execution trace record for step debugging.
#[derive(Debug, Clone)]
pub struct TraceRecord {
    pub pc: usize,
    pub opcode: Opcode,
    pub stack_snapshot: Vec<String>,
    pub register_snapshot: Vec<String>,
}

/// The CVM virtual machine.
pub struct Vm<C: CryptoDispatcher = NoCrypto, S: SandboxEnforcer = NoSandbox> {
    pub stack: Stack,
    pub registers: RegisterFile,
    pub memory: Memory,
    /// Program counter (byte offset into code section)
    pc: usize,
    /// The bytecode (code section only, header stripped)
    code: Vec<u8>,
    /// Call stack for CALL/RET
    call_stack: Vec<usize>,
    /// Crypto dispatcher
    crypto: C,
    /// Sandbox enforcer
    sandbox: S,
    /// Whether to record execution trace
    trace_enabled: bool,
    /// Execution trace
    pub trace: Vec<TraceRecord>,
    /// Total instructions executed
    pub steps: u64,
}

impl Vm<NoCrypto, NoSandbox> {
    /// Create a VM with no crypto support and no sandbox.
    pub fn new(bytecode: &[u8]) -> VmResult<Self> {
        Self::with_providers(bytecode, NoCrypto, NoSandbox)
    }
}

impl<C: CryptoDispatcher, S: SandboxEnforcer> Vm<C, S> {
    /// Create a VM with custom crypto dispatcher and sandbox.
    pub fn with_providers(bytecode: &[u8], crypto: C, sandbox: S) -> VmResult<Self> {
        let code = Self::validate_and_extract(bytecode)?;
        Ok(Self {
            stack: Stack::new(),
            registers: RegisterFile::new(),
            memory: Memory::new(),
            pc: 0,
            code,
            call_stack: Vec::new(),
            crypto,
            sandbox,
            trace_enabled: false,
            trace: Vec::new(),
            steps: 0,
        })
    }

    /// Load raw code (no header) — used by tests and assembler.
    pub fn from_raw_code(code: Vec<u8>, crypto: C, sandbox: S) -> Self {
        Self {
            stack: Stack::new(),
            registers: RegisterFile::new(),
            memory: Memory::new(),
            pc: 0,
            code,
            call_stack: Vec::new(),
            crypto,
            sandbox,
            trace_enabled: false,
            trace: Vec::new(),
            steps: 0,
        }
    }

    pub fn enable_trace(&mut self) { self.trace_enabled = true; }

    /// Validate bytecode header and extract the code section.
    fn validate_and_extract(bytecode: &[u8]) -> VmResult<Vec<u8>> {
        if bytecode.len() < HEADER_SIZE {
            return Err(VmError::InvalidBytecode("file too short for header".into()));
        }
        if bytecode[0..4] != CVM_MAGIC {
            return Err(VmError::InvalidBytecode("invalid magic bytes".into()));
        }
        let _version_major = bytecode[4];
        let _version_minor = bytecode[5];
        let code_size = u32::from_le_bytes([bytecode[8], bytecode[9], bytecode[10], bytecode[11]]) as usize;
        if bytecode.len() < HEADER_SIZE + code_size {
            return Err(VmError::InvalidBytecode(
                format!("code section truncated: expected {} bytes, got {}", code_size, bytecode.len() - HEADER_SIZE)
            ));
        }
        Ok(bytecode[HEADER_SIZE..HEADER_SIZE + code_size].to_vec())
    }

    /// Build a bytecode file with proper header from raw code.
    pub fn build_bytecode(code: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + code.len());
        out.extend_from_slice(&CVM_MAGIC);
        out.push(0x01); // version major
        out.push(0x00); // version minor
        out.extend_from_slice(&[0x00, 0x00]); // flags
        out.extend_from_slice(&(code.len() as u32).to_le_bytes());
        out.extend_from_slice(code);
        out
    }

    /// Execute the loaded program until HALT or error.
    pub fn execute(&mut self) -> VmResult<()> {
        loop {
            if self.pc >= self.code.len() {
                return Err(VmError::ProgramCounterOutOfBounds {
                    pc: self.pc, code_size: self.code.len(),
                });
            }

            let opcode_byte = self.code[self.pc];
            let opcode = Opcode::from_byte(opcode_byte)?;

            // Sandbox check
            self.sandbox.pre_execute(opcode)?;

            // Record trace if enabled
            if self.trace_enabled {
                self.trace.push(TraceRecord {
                    pc: self.pc,
                    opcode,
                    stack_snapshot: self.stack.dump(),
                    register_snapshot: self.registers.dump(),
                });
            }

            self.pc += 1;
            self.steps += 1;

            match self.execute_instruction(opcode) {
                Ok(()) => {}
                Err(VmError::HaltReached) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// Read a u8 operand and advance PC.
    fn read_u8(&mut self) -> VmResult<u8> {
        if self.pc >= self.code.len() {
            return Err(VmError::InvalidBytecode("unexpected end of code reading u8".into()));
        }
        let v = self.code[self.pc];
        self.pc += 1;
        Ok(v)
    }

    /// Read a u16 (little-endian) operand and advance PC.
    fn read_u16(&mut self) -> VmResult<u16> {
        if self.pc + 2 > self.code.len() {
            return Err(VmError::InvalidBytecode("unexpected end of code reading u16".into()));
        }
        let v = u16::from_le_bytes([self.code[self.pc], self.code[self.pc + 1]]);
        self.pc += 2;
        Ok(v)
    }

    /// Read a u32 (little-endian) operand and advance PC.
    fn read_u32(&mut self) -> VmResult<u32> {
        if self.pc + 4 > self.code.len() {
            return Err(VmError::InvalidBytecode("unexpected end of code reading u32".into()));
        }
        let v = u32::from_le_bytes([
            self.code[self.pc], self.code[self.pc + 1],
            self.code[self.pc + 2], self.code[self.pc + 3],
        ]);
        self.pc += 4;
        Ok(v)
    }

    /// Read an i64 (little-endian) operand and advance PC.
    fn read_i64(&mut self) -> VmResult<i64> {
        if self.pc + 8 > self.code.len() {
            return Err(VmError::InvalidBytecode("unexpected end of code reading i64".into()));
        }
        let v = i64::from_le_bytes([
            self.code[self.pc], self.code[self.pc + 1],
            self.code[self.pc + 2], self.code[self.pc + 3],
            self.code[self.pc + 4], self.code[self.pc + 5],
            self.code[self.pc + 6], self.code[self.pc + 7],
        ]);
        self.pc += 8;
        Ok(v)
    }

    /// Execute a single decoded instruction.
    fn execute_instruction(&mut self, opcode: Opcode) -> VmResult<()> {
        match opcode {
            // === Control Flow ===
            Opcode::Halt => Err(VmError::HaltReached),
            Opcode::Nop => Ok(()),

            // === Push Operations ===
            Opcode::PushInt => {
                let val = self.read_i64()?;
                self.stack.push(Value::Int(val))
            }
            Opcode::PushBytes => {
                let len = self.read_u16()? as usize;
                if self.pc + len > self.code.len() {
                    return Err(VmError::InvalidBytecode("PUSH_BYTES data truncated".into()));
                }
                let data = self.code[self.pc..self.pc + len].to_vec();
                self.pc += len;
                self.stack.push(Value::Bytes(data))
            }
            Opcode::PushBool => {
                let val = self.read_u8()?;
                self.stack.push(Value::Bool(val != 0))
            }

            // === Stack Operations ===
            Opcode::Pop => { self.stack.pop()?; Ok(()) }
            Opcode::Dup => self.stack.dup(),
            Opcode::Swap => self.stack.swap(),

            // === Jumps ===
            Opcode::Jmp => {
                let addr = self.read_u32()? as usize;
                self.pc = addr;
                Ok(())
            }
            Opcode::Jz => {
                let addr = self.read_u32()? as usize;
                let val = self.stack.pop()?;
                if !val.is_truthy() { self.pc = addr; }
                Ok(())
            }
            Opcode::Jnz => {
                let addr = self.read_u32()? as usize;
                let val = self.stack.pop()?;
                if val.is_truthy() { self.pc = addr; }
                Ok(())
            }

            // === Call/Ret ===
            Opcode::Call => {
                let addr = self.read_u32()? as usize;
                self.call_stack.push(self.pc);
                self.pc = addr;
                Ok(())
            }
            Opcode::Ret => {
                let ret_addr = self.call_stack.pop()
                    .ok_or(VmError::CallStackUnderflow)?;
                self.pc = ret_addr;
                Ok(())
            }

            // === Arithmetic ===
            Opcode::Add => self.binary_int_op(|a, b| Ok(a.wrapping_add(b))),
            Opcode::Sub => self.binary_int_op(|a, b| Ok(a.wrapping_sub(b))),
            Opcode::Mul => self.binary_int_op(|a, b| Ok(a.wrapping_mul(b))),
            Opcode::Div => self.binary_int_op(|a, b| {
                if b == 0 { Err(VmError::DivisionByZero) } else { Ok(a / b) }
            }),
            Opcode::Mod => self.binary_int_op(|a, b| {
                if b == 0 { Err(VmError::DivisionByZero) } else { Ok(a % b) }
            }),

            // === Comparison ===
            Opcode::Eq => {
                let b = self.stack.pop()?;
                let a = self.stack.pop()?;
                self.stack.push(Value::Bool(a == b))
            }
            Opcode::Neq => {
                let b = self.stack.pop()?;
                let a = self.stack.pop()?;
                self.stack.push(Value::Bool(a != b))
            }
            Opcode::Lt => self.compare_int_op(|a, b| a < b),
            Opcode::Gt => self.compare_int_op(|a, b| a > b),

            // === Registers ===
            Opcode::SetReg => {
                let reg = self.read_u8()?;
                let val = self.stack.pop()?;
                self.registers.set(reg, val)
            }
            Opcode::GetReg => {
                let reg = self.read_u8()?;
                let val = self.registers.get(reg)?.clone();
                self.stack.push(val)
            }

            // === Memory ===
            Opcode::Alloc => {
                let size = self.stack.pop()?.as_int()? as usize;
                let addr = self.memory.alloc(size)?;
                self.stack.push(Value::Int(addr as i64))
            }
            Opcode::Free => {
                let addr = self.stack.pop()?.as_int()? as u32;
                self.memory.free(addr)
            }
            Opcode::MLoad => {
                let len = self.stack.pop()?.as_int()? as usize;
                let addr = self.stack.pop()?.as_int()? as u32;
                let data = self.memory.load(addr, len)?;
                self.stack.push(Value::Bytes(data))
            }
            Opcode::MStore => {
                let data = self.stack.pop()?.into_bytes()?;
                let addr = self.stack.pop()?.as_int()? as u32;
                self.memory.store(addr, &data)
            }

            // === Crypto (delegated) ===
            op if op.is_crypto() => {
                self.crypto.dispatch(op, &mut self.stack)
            }

            // === I/O ===
            Opcode::Print => {
                let val = self.stack.pop()?;
                println!("{}", val);
                Ok(())
            }
            Opcode::Debug => {
                eprintln!("=== CVM Debug Dump ===");
                eprintln!("PC: 0x{:04X}", self.pc);
                eprintln!("Steps: {}", self.steps);
                eprintln!("Stack ({}):", self.stack.len());
                for line in self.stack.dump() { eprintln!("  {}", line); }
                eprintln!("Registers:");
                for line in self.registers.dump() { eprintln!("  {}", line); }
                eprintln!("Memory: {} bytes in {} blocks", self.memory.used(), self.memory.block_count());
                eprintln!("======================");
                Ok(())
            }

            // Should not reach here since from_byte already validates
            _ => Err(VmError::InvalidOpcode(opcode.to_byte())),
        }
    }

    /// Helper for binary integer operations.
    fn binary_int_op<F>(&mut self, op: F) -> VmResult<()>
    where F: FnOnce(i64, i64) -> VmResult<i64>
    {
        let b = self.stack.pop()?.as_int()?;
        let a = self.stack.pop()?.as_int()?;
        let result = op(a, b)?;
        self.stack.push(Value::Int(result))
    }

    /// Helper for integer comparison operations.
    fn compare_int_op<F>(&mut self, op: F) -> VmResult<()>
    where F: FnOnce(i64, i64) -> bool
    {
        let b = self.stack.pop()?.as_int()?;
        let a = self.stack.pop()?.as_int()?;
        self.stack.push(Value::Bool(op(a, b)))
    }

    pub fn pc(&self) -> usize { self.pc }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vm(code: Vec<u8>) -> Vm<NoCrypto, NoSandbox> {
        Vm::from_raw_code(code, NoCrypto, NoSandbox)
    }

    #[test]
    fn test_push_int_halt() {
        let mut code = vec![Opcode::PushInt.to_byte()];
        code.extend_from_slice(&42i64.to_le_bytes());
        code.push(Opcode::Halt.to_byte());
        let mut vm = make_vm(code);
        vm.execute().unwrap();
        assert_eq!(vm.stack.pop().unwrap(), Value::Int(42));
    }

    #[test]
    fn test_arithmetic() {
        let mut code = Vec::new();
        // PUSH 10, PUSH 3, ADD => 13
        code.push(Opcode::PushInt.to_byte()); code.extend_from_slice(&10i64.to_le_bytes());
        code.push(Opcode::PushInt.to_byte()); code.extend_from_slice(&3i64.to_le_bytes());
        code.push(Opcode::Add.to_byte());
        code.push(Opcode::Halt.to_byte());
        let mut vm = make_vm(code);
        vm.execute().unwrap();
        assert_eq!(vm.stack.pop().unwrap(), Value::Int(13));
    }

    #[test]
    fn test_division_by_zero() {
        let mut code = Vec::new();
        code.push(Opcode::PushInt.to_byte()); code.extend_from_slice(&10i64.to_le_bytes());
        code.push(Opcode::PushInt.to_byte()); code.extend_from_slice(&0i64.to_le_bytes());
        code.push(Opcode::Div.to_byte());
        code.push(Opcode::Halt.to_byte());
        let mut vm = make_vm(code);
        assert!(matches!(vm.execute(), Err(VmError::DivisionByZero)));
    }

    #[test]
    fn test_registers() {
        let mut code = Vec::new();
        code.push(Opcode::PushInt.to_byte()); code.extend_from_slice(&99i64.to_le_bytes());
        code.push(Opcode::SetReg.to_byte()); code.push(3);
        code.push(Opcode::GetReg.to_byte()); code.push(3);
        code.push(Opcode::Halt.to_byte());
        let mut vm = make_vm(code);
        vm.execute().unwrap();
        assert_eq!(vm.stack.pop().unwrap(), Value::Int(99));
    }

    #[test]
    fn test_jump() {
        let mut code = Vec::new();
        // JMP over the first PUSH to the HALT
        code.push(Opcode::Jmp.to_byte());
        let halt_pos = 1 + 4 + 1 + 8; // jmp(1+4) + push_int(1+8) = 14
        code.extend_from_slice(&(halt_pos as u32).to_le_bytes());
        // This should be skipped:
        code.push(Opcode::PushInt.to_byte()); code.extend_from_slice(&999i64.to_le_bytes());
        // Land here:
        code.push(Opcode::Halt.to_byte());
        let mut vm = make_vm(code);
        vm.execute().unwrap();
        assert!(vm.stack.is_empty()); // 999 was never pushed
    }

    #[test]
    fn test_bytecode_header() {
        let raw_code = vec![
            Opcode::PushInt.to_byte(), 7, 0, 0, 0, 0, 0, 0, 0,
            Opcode::Halt.to_byte(),
        ];
        let bytecode = Vm::<NoCrypto, NoSandbox>::build_bytecode(&raw_code);
        let mut vm = Vm::new(&bytecode).unwrap();
        vm.execute().unwrap();
        assert_eq!(vm.stack.pop().unwrap(), Value::Int(7));
    }

    #[test]
    fn test_call_ret() {
        let mut code = Vec::new();
        // CALL to offset 10
        code.push(Opcode::Call.to_byte());
        code.extend_from_slice(&10u32.to_le_bytes()); // 5 bytes
        // After CALL returns, we land here (offset 5)
        code.push(Opcode::Halt.to_byte()); // offset 5 -> 6 total from start

        // Pad to offset 10
        while code.len() < 10 { code.push(Opcode::Nop.to_byte()); }

        // Subroutine at offset 10
        code.push(Opcode::PushInt.to_byte());
        code.extend_from_slice(&42i64.to_le_bytes());
        code.push(Opcode::Ret.to_byte());

        let mut vm = make_vm(code);
        vm.execute().unwrap();
        assert_eq!(vm.stack.pop().unwrap(), Value::Int(42));
    }
}
