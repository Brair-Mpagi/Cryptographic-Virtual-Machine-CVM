// CVM Assembler — Lexer (tokenizer for .cvmasm files)

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// An instruction mnemonic like PUSH_INT, SHA256, HALT
    Mnemonic(String),
    /// A label definition like "start:"
    Label(String),
    /// A label reference (used as jump target)
    LabelRef(String),
    /// An integer literal (decimal or hex with 0x prefix)
    IntLiteral(i64),
    /// A byte string literal like "hello"
    StringLiteral(Vec<u8>),
    /// A hex byte literal like 0xDEADBEEF (pushed as Bytes)
    HexBytes(Vec<u8>),
    /// A register reference R0–R7
    Register(u8),
    /// Boolean literal
    BoolLiteral(bool),
    /// End of line
    Newline,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::Mnemonic(s) => write!(f, "Mnemonic({})", s),
            Token::Label(s) => write!(f, "Label({}:)", s),
            Token::LabelRef(s) => write!(f, "LabelRef({})", s),
            Token::IntLiteral(v) => write!(f, "Int({})", v),
            Token::StringLiteral(v) => write!(f, "String({} bytes)", v.len()),
            Token::HexBytes(v) => write!(f, "HexBytes({} bytes)", v.len()),
            Token::Register(r) => write!(f, "R{}", r),
            Token::BoolLiteral(b) => write!(f, "Bool({})", b),
            Token::Newline => write!(f, "\\n"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LexError {
    #[error("line {line}: {message}")]
    Error { line: usize, message: String },
}

/// Tokenize a .cvmasm source string into a flat list of tokens.
pub fn tokenize(source: &str) -> Result<Vec<Token>, LexError> {
    let mut tokens = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let line_num = line_num + 1;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        // Strip inline comments
        let line = if let Some(pos) = line.find(';') {
            line[..pos].trim()
        } else {
            line
        };

        if line.is_empty() { continue; }

        let mut pos = 0;

        while pos < line.len() {
            // Skip whitespace
            while pos < line.len() && line.as_bytes()[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if pos >= line.len() { break; }

            let rest = &line[pos..];

            // String literal
            if rest.starts_with('"') {
                let end = rest[1..].find('"').ok_or(LexError::Error {
                    line: line_num,
                    message: "unterminated string literal".into(),
                })?;
                let s = &rest[1..1 + end];
                tokens.push(Token::StringLiteral(s.as_bytes().to_vec()));
                pos += 2 + end;
                continue;
            }

            // Grab the next word
            let word_end = rest.find(|c: char| c.is_ascii_whitespace() || c == ',')
                .unwrap_or(rest.len());
            let word = &rest[..word_end];
            pos += word_end;

            // Skip comma
            if pos < line.len() && line.as_bytes()[pos] == b',' {
                pos += 1;
            }

            if word.is_empty() { continue; }

            // Label definition (ends with ':')
            if word.ends_with(':') {
                let name = &word[..word.len() - 1];
                tokens.push(Token::Label(name.to_string()));
                continue;
            }

            // Register (R0–R7)
            if word.len() == 2 && word.starts_with('R') || word.starts_with('r') {
                if let Some(digit) = word.chars().nth(1) {
                    if digit.is_ascii_digit() {
                        let reg = digit as u8 - b'0';
                        if reg < 8 {
                            tokens.push(Token::Register(reg));
                            continue;
                        }
                    }
                }
            }

            // Boolean
            if word.eq_ignore_ascii_case("true") {
                tokens.push(Token::BoolLiteral(true));
                continue;
            }
            if word.eq_ignore_ascii_case("false") {
                tokens.push(Token::BoolLiteral(false));
                continue;
            }

            // Hex integer (0x prefix but treated as integer if it fits)
            if word.starts_with("0x") || word.starts_with("0X") {
                let hex_str = &word[2..];
                if let Ok(v) = i64::from_str_radix(hex_str, 16) {
                    tokens.push(Token::IntLiteral(v));
                    continue;
                }
                // If too large for i64, treat as hex bytes
                let bytes = hex_decode(hex_str).map_err(|_| LexError::Error {
                    line: line_num,
                    message: format!("invalid hex literal: {}", word),
                })?;
                tokens.push(Token::HexBytes(bytes));
                continue;
            }

            // Negative integer
            if word.starts_with('-') {
                if let Ok(v) = word.parse::<i64>() {
                    tokens.push(Token::IntLiteral(v));
                    continue;
                }
            }

            // Decimal integer
            if word.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                if let Ok(v) = word.parse::<i64>() {
                    tokens.push(Token::IntLiteral(v));
                    continue;
                }
            }

            // Check if it's a known mnemonic
            if cvm_core::Opcode::from_mnemonic(word).is_some() {
                tokens.push(Token::Mnemonic(word.to_uppercase()));
                continue;
            }

            // Otherwise, treat as label reference
            tokens.push(Token::LabelRef(word.to_string()));
        }

        tokens.push(Token::Newline);
    }

    Ok(tokens)
}

/// Simple hex decoder.
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 { return Err(()); }
    (0..s.len()).step_by(2).map(|i| {
        u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ())
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_tokenize() {
        let tokens = tokenize("PUSH_INT 42\nHALT").unwrap();
        assert!(matches!(&tokens[0], Token::Mnemonic(s) if s == "PUSH_INT"));
        assert!(matches!(&tokens[1], Token::IntLiteral(42)));
    }

    #[test]
    fn test_label() {
        let tokens = tokenize("start:\n  HALT").unwrap();
        assert!(matches!(&tokens[0], Token::Label(s) if s == "start"));
    }

    #[test]
    fn test_register() {
        let tokens = tokenize("SETREG R3").unwrap();
        assert!(matches!(&tokens[1], Token::Register(3)));
    }

    #[test]
    fn test_comments() {
        let tokens = tokenize("; full comment\nHALT ; inline").unwrap();
        assert!(matches!(&tokens[0], Token::Mnemonic(s) if s == "HALT"));
    }
}
