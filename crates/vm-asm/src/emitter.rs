// CVM Assembler — Bytecode emitter
//
// Encodes parsed instructions into CVM bytecode with proper file header.

use crate::parser::{Instruction, Operand};
use cvm_core::vm::CVM_MAGIC;

/// Emit bytecode from a list of parsed instructions.
/// Returns the complete .cvmb file contents (header + code).
pub fn emit(instructions: &[Instruction]) -> Vec<u8> {
    let code = emit_code(instructions);
    build_file(&code)
}

/// Emit just the code section (no header).
pub fn emit_code(instructions: &[Instruction]) -> Vec<u8> {
    let mut code = Vec::new();
    for instr in instructions {
        code.push(instr.opcode.to_byte());
        for operand in &instr.operands {
            match operand {
                Operand::Int(v) => code.extend_from_slice(&v.to_le_bytes()),
                Operand::Bytes(b) => {
                    code.extend_from_slice(&(b.len() as u16).to_le_bytes());
                    code.extend_from_slice(b);
                }
                Operand::Bool(v) => code.push(if *v { 1 } else { 0 }),
                Operand::Register(r) => code.push(*r),
                Operand::Address(a) => code.extend_from_slice(&a.to_le_bytes()),
            }
        }
    }
    code
}

/// Wrap a code section with the CVM file header.
pub fn build_file(code: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + code.len());
    out.extend_from_slice(&CVM_MAGIC);     // magic: "CVM\0"
    out.push(0x01);                         // version major
    out.push(0x00);                         // version minor
    out.extend_from_slice(&[0x00, 0x00]);   // flags (reserved)
    out.extend_from_slice(&(code.len() as u32).to_le_bytes()); // code_size
    out.extend_from_slice(code);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Operand;
    use cvm_core::Opcode;

    #[test]
    fn test_emit_halt() {
        let instrs = vec![Instruction {
            opcode: Opcode::Halt,
            operands: vec![],
        }];
        let bytecode = emit(&instrs);
        // Header (12) + HALT (1) = 13
        assert_eq!(bytecode.len(), 13);
        assert_eq!(&bytecode[0..4], &CVM_MAGIC);
        assert_eq!(bytecode[12], 0x00); // HALT
    }

    #[test]
    fn test_emit_push_int() {
        let instrs = vec![
            Instruction {
                opcode: Opcode::PushInt,
                operands: vec![Operand::Int(42)],
            },
            Instruction { opcode: Opcode::Halt, operands: vec![] },
        ];
        let code = emit_code(&instrs);
        assert_eq!(code[0], Opcode::PushInt.to_byte());
        let val = i64::from_le_bytes(code[1..9].try_into().unwrap());
        assert_eq!(val, 42);
    }
}
