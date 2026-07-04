// CVM Assembler — Two-pass parser
//
// Pass 1: collect label addresses
// Pass 2: resolve label references and build instruction list

use crate::lexer::{Token, LexError};
use cvm_core::Opcode;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum Operand {
    Int(i64),
    Bytes(Vec<u8>),
    Bool(bool),
    Register(u8),
    Address(u32),
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub opcode: Opcode,
    pub operands: Vec<Operand>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("parse error: {0}")]
    Error(String),
    #[error(transparent)]
    Lex(#[from] LexError),
}

impl Instruction {
    /// Calculate the byte size of this instruction when encoded.
    pub fn encoded_size(&self) -> usize {
        let mut size = 1; // opcode byte
        for op in &self.operands {
            size += match op {
                Operand::Int(_) => 8,
                Operand::Bytes(b) => 2 + b.len(), // u16 len + data
                Operand::Bool(_) => 1,
                Operand::Register(_) => 1,
                Operand::Address(_) => 4,
            };
        }
        size
    }
}

/// Parse tokens into instructions with resolved labels (two-pass).
pub fn parse(tokens: &[Token]) -> Result<Vec<Instruction>, ParseError> {
    // Pass 1: collect label offsets
    let labels = collect_labels(tokens)?;
    // Pass 2: build instructions with resolved addresses
    resolve_instructions(tokens, &labels)
}

/// Pass 1: scan tokens to determine byte offset of each label.
fn collect_labels(tokens: &[Token]) -> Result<HashMap<String, u32>, ParseError> {
    let mut labels = HashMap::new();
    let mut offset: u32 = 0;
    let mut i = 0;

    while i < tokens.len() {
        match &tokens[i] {
            Token::Label(name) => {
                if labels.contains_key(name) {
                    return Err(ParseError::Error(format!("duplicate label: {}", name)));
                }
                labels.insert(name.clone(), offset);
                i += 1;
            }
            Token::Newline => { i += 1; }
            Token::Mnemonic(m) => {
                let opcode = Opcode::from_mnemonic(m)
                    .ok_or_else(|| ParseError::Error(format!("unknown mnemonic: {}", m)))?;
                i += 1;
                // Calculate instruction size by scanning operands
                let size = estimate_instruction_size(opcode, tokens, &mut i)?;
                offset += size as u32;
            }
            other => {
                return Err(ParseError::Error(format!("unexpected token: {}", other)));
            }
        }
    }

    Ok(labels)
}

/// Estimate instruction size by scanning its operands (pass 1).
fn estimate_instruction_size(opcode: Opcode, tokens: &[Token], i: &mut usize) -> Result<usize, ParseError> {
    let mut size = 1usize; // opcode byte

    match opcode {
        Opcode::PushInt => {
            skip_operand(tokens, i)?;
            size += 8;
        }
        Opcode::PushBytes => {
            if *i < tokens.len() {
                match &tokens[*i] {
                    Token::StringLiteral(s) => { size += 2 + s.len(); *i += 1; }
                    Token::HexBytes(b) => { size += 2 + b.len(); *i += 1; }
                    _ => return Err(ParseError::Error("PUSH_BYTES requires string or hex literal".into())),
                }
            }
        }
        Opcode::PushBool => {
            skip_operand(tokens, i)?;
            size += 1;
        }
        Opcode::SetReg | Opcode::GetReg => {
            skip_operand(tokens, i)?;
            size += 1;
        }
        Opcode::Jmp | Opcode::Jz | Opcode::Jnz | Opcode::Call => {
            skip_operand(tokens, i)?;
            size += 4;
        }
        _ => {} // No operands
    }

    Ok(size)
}

fn skip_operand(tokens: &[Token], i: &mut usize) -> Result<(), ParseError> {
    if *i < tokens.len() && !matches!(&tokens[*i], Token::Newline) {
        *i += 1;
        Ok(())
    } else {
        Err(ParseError::Error("expected operand".into()))
    }
}

/// Pass 2: build instruction list with resolved label addresses.
fn resolve_instructions(tokens: &[Token], labels: &HashMap<String, u32>) -> Result<Vec<Instruction>, ParseError> {
    let mut instructions = Vec::new();
    let mut i = 0;

    while i < tokens.len() {
        match &tokens[i] {
            Token::Label(_) | Token::Newline => { i += 1; }
            Token::Mnemonic(m) => {
                let opcode = Opcode::from_mnemonic(m).unwrap();
                i += 1;
                let operands = parse_operands(opcode, tokens, &mut i, labels)?;
                instructions.push(Instruction { opcode, operands });
            }
            other => {
                return Err(ParseError::Error(format!("unexpected token in pass 2: {}", other)));
            }
        }
    }

    Ok(instructions)
}

/// Parse operands for a specific opcode.
fn parse_operands(
    opcode: Opcode,
    tokens: &[Token],
    i: &mut usize,
    labels: &HashMap<String, u32>,
) -> Result<Vec<Operand>, ParseError> {
    let mut ops = Vec::new();

    match opcode {
        Opcode::PushInt => {
            match tokens.get(*i) {
                Some(Token::IntLiteral(v)) => { ops.push(Operand::Int(*v)); *i += 1; }
                _ => return Err(ParseError::Error("PUSH_INT requires integer operand".into())),
            }
        }
        Opcode::PushBytes => {
            match tokens.get(*i) {
                Some(Token::StringLiteral(s)) => { ops.push(Operand::Bytes(s.clone())); *i += 1; }
                Some(Token::HexBytes(b)) => { ops.push(Operand::Bytes(b.clone())); *i += 1; }
                _ => return Err(ParseError::Error("PUSH_BYTES requires string or hex literal".into())),
            }
        }
        Opcode::PushBool => {
            match tokens.get(*i) {
                Some(Token::BoolLiteral(v)) => { ops.push(Operand::Bool(*v)); *i += 1; }
                Some(Token::IntLiteral(v)) => { ops.push(Operand::Bool(*v != 0)); *i += 1; }
                _ => return Err(ParseError::Error("PUSH_BOOL requires boolean operand".into())),
            }
        }
        Opcode::SetReg | Opcode::GetReg => {
            match tokens.get(*i) {
                Some(Token::Register(r)) => { ops.push(Operand::Register(*r)); *i += 1; }
                Some(Token::IntLiteral(v)) => { ops.push(Operand::Register(*v as u8)); *i += 1; }
                _ => return Err(ParseError::Error(format!("{} requires register operand", opcode))),
            }
        }
        Opcode::Jmp | Opcode::Jz | Opcode::Jnz | Opcode::Call => {
            match tokens.get(*i) {
                Some(Token::LabelRef(name)) => {
                    let addr = labels.get(name)
                        .ok_or_else(|| ParseError::Error(format!("undefined label: {}", name)))?;
                    ops.push(Operand::Address(*addr));
                    *i += 1;
                }
                Some(Token::IntLiteral(v)) => { ops.push(Operand::Address(*v as u32)); *i += 1; }
                _ => return Err(ParseError::Error(format!("{} requires label or address", opcode))),
            }
        }
        _ => {} // No operands needed
    }

    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;

    #[test]
    fn test_simple_parse() {
        let tokens = tokenize("PUSH_INT 42\nHALT").unwrap();
        let instrs = parse(&tokens).unwrap();
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].opcode, Opcode::PushInt);
        assert_eq!(instrs[1].opcode, Opcode::Halt);
    }

    #[test]
    fn test_label_resolution() {
        let source = "JMP end\nPUSH_INT 99\nend:\nHALT";
        let tokens = tokenize(source).unwrap();
        let instrs = parse(&tokens).unwrap();
        // JMP(1+4=5) + PUSH_INT(1+8=9) = 14 => end label at offset 14
        match &instrs[0].operands[0] {
            Operand::Address(addr) => assert_eq!(*addr, 14),
            _ => panic!("expected Address operand"),
        }
    }

    #[test]
    fn test_undefined_label() {
        let tokens = tokenize("JMP nowhere").unwrap();
        assert!(parse(&tokens).is_err());
    }
}
