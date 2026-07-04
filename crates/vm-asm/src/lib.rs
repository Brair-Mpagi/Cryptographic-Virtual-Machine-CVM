// CVM Assembler — Public API

pub mod lexer;
pub mod parser;
pub mod emitter;

use lexer::LexError;
use parser::ParseError;

#[derive(Debug, thiserror::Error)]
pub enum AsmError {
    #[error(transparent)]
    Lex(#[from] LexError),
    #[error(transparent)]
    Parse(#[from] ParseError),
}

/// Assemble a .cvmasm source string into a .cvmb bytecode file.
/// Returns the complete bytecode (header + code section).
pub fn assemble(source: &str) -> Result<Vec<u8>, AsmError> {
    let tokens = lexer::tokenize(source)?;
    let instructions = parser::parse(&tokens)?;
    Ok(emitter::emit(&instructions))
}

/// Assemble and return just the raw code (no header).
pub fn assemble_raw(source: &str) -> Result<Vec<u8>, AsmError> {
    let tokens = lexer::tokenize(source)?;
    let instructions = parser::parse(&tokens)?;
    Ok(emitter::emit_code(&instructions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_simple() {
        let source = "PUSH_INT 42\nPRINT\nHALT";
        let bytecode = assemble(source).unwrap();
        assert!(bytecode.len() > 12); // header + code
        assert_eq!(&bytecode[0..4], &[0x43, 0x56, 0x4D, 0x00]);
    }

    #[test]
    fn test_assemble_with_labels() {
        let source = r#"
            PUSH_INT 10
            SETREG R0
        loop:
            GETREG R0
            PUSH_INT 1
            SUB
            DUP
            SETREG R0
            JNZ loop
            POP
            HALT
        "#;
        let bytecode = assemble(source).unwrap();
        assert!(bytecode.len() > 12);
    }
}
