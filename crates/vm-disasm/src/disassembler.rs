// CVM Disassembler — Converts .cvmb bytecode to human-readable assembly

use cvm_core::{Opcode, VmError, VmResult, CVM_MAGIC, HEADER_SIZE};

/// Disassemble a complete .cvmb file into readable assembly.
pub fn disassemble(bytecode: &[u8]) -> VmResult<String> {
    // Validate header
    if bytecode.len() < HEADER_SIZE {
        return Err(VmError::InvalidBytecode("file too short".into()));
    }
    if bytecode[0..4] != CVM_MAGIC {
        return Err(VmError::InvalidBytecode("invalid magic bytes".into()));
    }

    let version_major = bytecode[4];
    let version_minor = bytecode[5];
    let code_size = u32::from_le_bytes([bytecode[8], bytecode[9], bytecode[10], bytecode[11]]) as usize;

    if bytecode.len() < HEADER_SIZE + code_size {
        return Err(VmError::InvalidBytecode("code section truncated".into()));
    }

    let code = &bytecode[HEADER_SIZE..HEADER_SIZE + code_size];

    let mut output = String::new();
    output.push_str(&format!("; CVM Bytecode v{}.{}\n", version_major, version_minor));
    output.push_str(&format!("; Code size: {} bytes\n\n", code_size));

    disassemble_code(code, &mut output)?;
    Ok(output)
}

/// Disassemble raw code bytes (no header).
pub fn disassemble_raw(code: &[u8]) -> VmResult<String> {
    let mut output = String::new();
    disassemble_code(code, &mut output)?;
    Ok(output)
}

fn disassemble_code(code: &[u8], output: &mut String) -> VmResult<()> {
    let mut pc = 0;

    while pc < code.len() {
        let addr = pc;
        let opcode_byte = code[pc];
        let opcode = Opcode::from_byte(opcode_byte)?;
        pc += 1;

        let line = match opcode {
            Opcode::PushInt => {
                if pc + 8 > code.len() {
                    return Err(VmError::InvalidBytecode("PUSH_INT truncated".into()));
                }
                let val = i64::from_le_bytes(code[pc..pc+8].try_into().unwrap());
                pc += 8;
                format!("0x{:04X}:  PUSH_INT {}", addr, val)
            }
            Opcode::PushBytes => {
                if pc + 2 > code.len() {
                    return Err(VmError::InvalidBytecode("PUSH_BYTES truncated".into()));
                }
                let len = u16::from_le_bytes([code[pc], code[pc+1]]) as usize;
                pc += 2;
                if pc + len > code.len() {
                    return Err(VmError::InvalidBytecode("PUSH_BYTES data truncated".into()));
                }
                let data = &code[pc..pc+len];
                pc += len;
                // Try to display as UTF-8 string
                if let Ok(s) = std::str::from_utf8(data) {
                    format!("0x{:04X}:  PUSH_BYTES \"{}\"", addr, s)
                } else {
                    let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
                    format!("0x{:04X}:  PUSH_BYTES 0x{}", addr, hex)
                }
            }
            Opcode::PushBool => {
                if pc >= code.len() {
                    return Err(VmError::InvalidBytecode("PUSH_BOOL truncated".into()));
                }
                let val = code[pc] != 0;
                pc += 1;
                format!("0x{:04X}:  PUSH_BOOL {}", addr, val)
            }
            Opcode::Jmp | Opcode::Jz | Opcode::Jnz | Opcode::Call => {
                if pc + 4 > code.len() {
                    return Err(VmError::InvalidBytecode(format!("{} truncated", opcode)));
                }
                let target = u32::from_le_bytes(code[pc..pc+4].try_into().unwrap());
                pc += 4;
                format!("0x{:04X}:  {} 0x{:04X}", addr, opcode.mnemonic(), target)
            }
            Opcode::SetReg | Opcode::GetReg => {
                if pc >= code.len() {
                    return Err(VmError::InvalidBytecode(format!("{} truncated", opcode)));
                }
                let reg = code[pc];
                pc += 1;
                format!("0x{:04X}:  {} R{}", addr, opcode.mnemonic(), reg)
            }
            _ => {
                format!("0x{:04X}:  {}", addr, opcode.mnemonic())
            }
        };

        output.push_str(&line);
        output.push('\n');
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_simple() {
        let mut code = Vec::new();
        code.push(Opcode::PushInt.to_byte());
        code.extend_from_slice(&42i64.to_le_bytes());
        code.push(Opcode::Print.to_byte());
        code.push(Opcode::Halt.to_byte());

        let output = disassemble_raw(&code).unwrap();
        assert!(output.contains("PUSH_INT 42"));
        assert!(output.contains("PRINT"));
        assert!(output.contains("HALT"));
    }

    #[test]
    fn test_disassemble_with_header() {
        use cvm_core::Vm;
        let code = vec![Opcode::Halt.to_byte()];
        let bytecode = Vm::<cvm_core::NoCrypto, cvm_core::NoSandbox>::build_bytecode(&code);
        let output = disassemble(&bytecode).unwrap();
        assert!(output.contains("HALT"));
    }
}
