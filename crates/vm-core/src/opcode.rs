// CVM Core — Opcode definitions

use crate::error::{VmError, VmResult};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    Halt = 0x00, Nop = 0x01, PushInt = 0x02, PushBytes = 0x03, PushBool = 0x04,
    Pop = 0x05, Dup = 0x06, Swap = 0x07, Jmp = 0x08, Jz = 0x09, Jnz = 0x0A,
    Call = 0x0B, Ret = 0x0C,
    Add = 0x10, Sub = 0x11, Mul = 0x12, Div = 0x13, Mod = 0x14,
    Eq = 0x15, Neq = 0x16, Lt = 0x17, Gt = 0x18,
    SetReg = 0x20, GetReg = 0x21,
    Alloc = 0x30, Free = 0x31, MLoad = 0x32, MStore = 0x33,
    Sha256 = 0x40, Sha3_256 = 0x41, Hmac = 0x42,
    AesEncrypt = 0x43, AesDecrypt = 0x44,
    RsaSign = 0x45, RsaVerify = 0x46,
    EcdsaSign = 0x47, EcdsaVerify = 0x48,
    RandBytes = 0x49, GenSymKey = 0x4A, GenRsaKey = 0x4B, GenEcKey = 0x4C,
    Print = 0x60, Debug = 0x61,
}

impl Opcode {
    pub fn from_byte(byte: u8) -> VmResult<Self> {
        match byte {
            0x00 => Ok(Opcode::Halt), 0x01 => Ok(Opcode::Nop),
            0x02 => Ok(Opcode::PushInt), 0x03 => Ok(Opcode::PushBytes),
            0x04 => Ok(Opcode::PushBool), 0x05 => Ok(Opcode::Pop),
            0x06 => Ok(Opcode::Dup), 0x07 => Ok(Opcode::Swap),
            0x08 => Ok(Opcode::Jmp), 0x09 => Ok(Opcode::Jz),
            0x0A => Ok(Opcode::Jnz), 0x0B => Ok(Opcode::Call),
            0x0C => Ok(Opcode::Ret),
            0x10 => Ok(Opcode::Add), 0x11 => Ok(Opcode::Sub),
            0x12 => Ok(Opcode::Mul), 0x13 => Ok(Opcode::Div),
            0x14 => Ok(Opcode::Mod), 0x15 => Ok(Opcode::Eq),
            0x16 => Ok(Opcode::Neq), 0x17 => Ok(Opcode::Lt),
            0x18 => Ok(Opcode::Gt),
            0x20 => Ok(Opcode::SetReg), 0x21 => Ok(Opcode::GetReg),
            0x30 => Ok(Opcode::Alloc), 0x31 => Ok(Opcode::Free),
            0x32 => Ok(Opcode::MLoad), 0x33 => Ok(Opcode::MStore),
            0x40 => Ok(Opcode::Sha256), 0x41 => Ok(Opcode::Sha3_256),
            0x42 => Ok(Opcode::Hmac), 0x43 => Ok(Opcode::AesEncrypt),
            0x44 => Ok(Opcode::AesDecrypt), 0x45 => Ok(Opcode::RsaSign),
            0x46 => Ok(Opcode::RsaVerify), 0x47 => Ok(Opcode::EcdsaSign),
            0x48 => Ok(Opcode::EcdsaVerify), 0x49 => Ok(Opcode::RandBytes),
            0x4A => Ok(Opcode::GenSymKey), 0x4B => Ok(Opcode::GenRsaKey),
            0x4C => Ok(Opcode::GenEcKey),
            0x60 => Ok(Opcode::Print), 0x61 => Ok(Opcode::Debug),
            _ => Err(VmError::InvalidOpcode(byte)),
        }
    }

    pub fn to_byte(self) -> u8 { self as u8 }

    pub fn mnemonic(self) -> &'static str {
        match self {
            Opcode::Halt => "HALT", Opcode::Nop => "NOP",
            Opcode::PushInt => "PUSH_INT", Opcode::PushBytes => "PUSH_BYTES",
            Opcode::PushBool => "PUSH_BOOL", Opcode::Pop => "POP",
            Opcode::Dup => "DUP", Opcode::Swap => "SWAP",
            Opcode::Jmp => "JMP", Opcode::Jz => "JZ", Opcode::Jnz => "JNZ",
            Opcode::Call => "CALL", Opcode::Ret => "RET",
            Opcode::Add => "ADD", Opcode::Sub => "SUB",
            Opcode::Mul => "MUL", Opcode::Div => "DIV", Opcode::Mod => "MOD",
            Opcode::Eq => "EQ", Opcode::Neq => "NEQ",
            Opcode::Lt => "LT", Opcode::Gt => "GT",
            Opcode::SetReg => "SETREG", Opcode::GetReg => "GETREG",
            Opcode::Alloc => "ALLOC", Opcode::Free => "FREE",
            Opcode::MLoad => "MLOAD", Opcode::MStore => "MSTORE",
            Opcode::Sha256 => "SHA256", Opcode::Sha3_256 => "SHA3_256",
            Opcode::Hmac => "HMAC", Opcode::AesEncrypt => "AES_ENCRYPT",
            Opcode::AesDecrypt => "AES_DECRYPT", Opcode::RsaSign => "RSA_SIGN",
            Opcode::RsaVerify => "RSA_VERIFY", Opcode::EcdsaSign => "ECDSA_SIGN",
            Opcode::EcdsaVerify => "ECDSA_VERIFY", Opcode::RandBytes => "RAND_BYTES",
            Opcode::GenSymKey => "GEN_SYM_KEY", Opcode::GenRsaKey => "GEN_RSA_KEY",
            Opcode::GenEcKey => "GEN_EC_KEY",
            Opcode::Print => "PRINT", Opcode::Debug => "DEBUG",
        }
    }

    pub fn from_mnemonic(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "HALT" => Some(Opcode::Halt), "NOP" => Some(Opcode::Nop),
            "PUSH_INT" => Some(Opcode::PushInt), "PUSH_BYTES" => Some(Opcode::PushBytes),
            "PUSH_BOOL" => Some(Opcode::PushBool), "POP" => Some(Opcode::Pop),
            "DUP" => Some(Opcode::Dup), "SWAP" => Some(Opcode::Swap),
            "JMP" => Some(Opcode::Jmp), "JZ" => Some(Opcode::Jz),
            "JNZ" => Some(Opcode::Jnz), "CALL" => Some(Opcode::Call),
            "RET" => Some(Opcode::Ret), "ADD" => Some(Opcode::Add),
            "SUB" => Some(Opcode::Sub), "MUL" => Some(Opcode::Mul),
            "DIV" => Some(Opcode::Div), "MOD" => Some(Opcode::Mod),
            "EQ" => Some(Opcode::Eq), "NEQ" => Some(Opcode::Neq),
            "LT" => Some(Opcode::Lt), "GT" => Some(Opcode::Gt),
            "SETREG" => Some(Opcode::SetReg), "GETREG" => Some(Opcode::GetReg),
            "ALLOC" => Some(Opcode::Alloc), "FREE" => Some(Opcode::Free),
            "MLOAD" => Some(Opcode::MLoad), "MSTORE" => Some(Opcode::MStore),
            "SHA256" => Some(Opcode::Sha256), "SHA3_256" => Some(Opcode::Sha3_256),
            "HMAC" => Some(Opcode::Hmac), "AES_ENCRYPT" => Some(Opcode::AesEncrypt),
            "AES_DECRYPT" => Some(Opcode::AesDecrypt), "RSA_SIGN" => Some(Opcode::RsaSign),
            "RSA_VERIFY" => Some(Opcode::RsaVerify), "ECDSA_SIGN" => Some(Opcode::EcdsaSign),
            "ECDSA_VERIFY" => Some(Opcode::EcdsaVerify), "RAND_BYTES" => Some(Opcode::RandBytes),
            "GEN_SYM_KEY" => Some(Opcode::GenSymKey), "GEN_RSA_KEY" => Some(Opcode::GenRsaKey),
            "GEN_EC_KEY" => Some(Opcode::GenEcKey),
            "PRINT" => Some(Opcode::Print), "DEBUG" => Some(Opcode::Debug),
            _ => None,
        }
    }

    /// Number of fixed operand bytes following the opcode byte.
    pub fn operand_size(self) -> usize {
        match self {
            Opcode::PushInt => 8,
            Opcode::Jmp | Opcode::Jz | Opcode::Jnz | Opcode::Call => 4,
            Opcode::PushBool | Opcode::SetReg | Opcode::GetReg => 1,
            Opcode::PushBytes => 0, // Variable-length: handled specially
            _ => 0,
        }
    }

    pub fn is_variable_length(self) -> bool { matches!(self, Opcode::PushBytes) }
    pub fn is_crypto(self) -> bool { (0x40..=0x5F).contains(&(self as u8)) }

    /// Gas cost per opcode category.
    pub fn gas_cost(self) -> u64 {
        match self {
            Opcode::GenRsaKey => 500,
            Opcode::RsaSign | Opcode::RsaVerify => 100,
            Opcode::EcdsaSign | Opcode::EcdsaVerify | Opcode::GenEcKey => 50,
            Opcode::AesEncrypt | Opcode::AesDecrypt => 20,
            Opcode::Sha256 | Opcode::Sha3_256 | Opcode::Hmac => 10,
            Opcode::GenSymKey | Opcode::RandBytes => 5,
            Opcode::Alloc | Opcode::Free | Opcode::MLoad | Opcode::MStore => 3,
            _ => 1,
        }
    }

    pub fn category(self) -> &'static str {
        match self as u8 {
            0x00..=0x0F => "Stack/Control",
            0x10..=0x1F => "Arithmetic",
            0x20..=0x2F => "Register",
            0x30..=0x3F => "Memory",
            0x40..=0x5F => "Crypto",
            0x60..=0x6F => "I/O",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mnemonic())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_byte() {
        for op in [Opcode::Halt, Opcode::PushInt, Opcode::Add, Opcode::SetReg, Opcode::Sha256, Opcode::Print, Opcode::Jmp] {
            assert_eq!(op, Opcode::from_byte(op.to_byte()).unwrap());
        }
    }

    #[test]
    fn test_roundtrip_mnemonic() {
        for op in [Opcode::Halt, Opcode::PushBytes, Opcode::AesEncrypt, Opcode::EcdsaVerify] {
            assert_eq!(op, Opcode::from_mnemonic(op.mnemonic()).unwrap());
        }
    }

    #[test]
    fn test_invalid_opcode() {
        assert!(Opcode::from_byte(0xFF).is_err());
    }

    #[test]
    fn test_is_crypto() {
        assert!(Opcode::Sha256.is_crypto());
        assert!(!Opcode::Add.is_crypto());
    }
}
