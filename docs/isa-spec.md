# CVM Instruction Set Architecture Specification v1.0

## 1. Bytecode File Format

### 1.1 File Header (12 bytes)

| Offset | Size | Field        | Description                          |
|--------|------|--------------|--------------------------------------|
| 0x00   | 4    | magic        | `0x43 0x56 0x4D 0x00` ("CVM\0")     |
| 0x04   | 2    | version      | ISA version (major.minor as u8.u8)   |
| 0x06   | 2    | flags        | Reserved, must be 0x0000             |
| 0x08   | 4    | code_size    | Size of code section in bytes (u32)  |

### 1.2 Sections

After the header, sections appear in order:

1. **Code Section** — `code_size` bytes of executable bytecode
2. **Data Section** — (future) static data referenced by LOAD instructions

## 2. Value Types

The VM is a typed stack machine. Every value on the stack or in a register carries a type tag.

| Tag | Type       | Representation       | Description                                |
|-----|------------|----------------------|--------------------------------------------|
| 0   | `Int`      | i64 (8 bytes)        | Signed 64-bit integer                      |
| 1   | `Bytes`    | Vec\<u8\>            | Variable-length byte array                 |
| 2   | `Bool`     | 1 byte (0 or 1)      | Boolean                                    |
| 3   | `KeyHandle`| u32 (4 bytes)        | Opaque reference into the VM key store     |

> **Security invariant**: `KeyHandle` values are opaque indices. Raw key material is NEVER placed on the operand stack. This prevents accidental key leakage through stack inspection or serialization.

## 3. Opcode Table

### 3.1 Encoding

Each instruction is encoded as:

```
[opcode: 1 byte] [operands: 0–8 bytes, depending on opcode]
```

### 3.2 Stack & Control Flow (0x00–0x0F)

| Opcode | Hex  | Mnemonic  | Operands          | Stack Effect          | Description                          |
|--------|------|-----------|-------------------|-----------------------|--------------------------------------|
| 0      | 0x00 | HALT      | —                 | —                     | Stop execution                       |
| 1      | 0x01 | NOP       | —                 | —                     | No operation                         |
| 2      | 0x02 | PUSH_INT  | imm: i64 (8B)    | → val                 | Push integer literal                 |
| 3      | 0x03 | PUSH_BYTES| len: u16, data    | → val                 | Push byte array (len + raw bytes)    |
| 4      | 0x04 | PUSH_BOOL | imm: u8 (1B)     | → val                 | Push boolean (0=false, 1=true)       |
| 5      | 0x05 | POP       | —                 | val →                 | Discard top of stack                 |
| 6      | 0x06 | DUP       | —                 | val → val val         | Duplicate top of stack               |
| 7      | 0x07 | SWAP      | —                 | a b → b a             | Swap top two values                  |
| 8      | 0x08 | JMP       | addr: u32 (4B)   | —                     | Unconditional jump                   |
| 9      | 0x09 | JZ        | addr: u32 (4B)   | cond →                | Jump if top is Int(0) or Bool(false) |
| 10     | 0x0A | JNZ       | addr: u32 (4B)   | cond →                | Jump if top is nonzero/true          |
| 11     | 0x0B | CALL      | addr: u32 (4B)   | — (pushes return addr)| Call subroutine                      |
| 12     | 0x0C | RET       | —                 | — (pops return addr)  | Return from subroutine               |

### 3.3 Arithmetic & Comparison (0x10–0x1F)

| Opcode | Hex  | Mnemonic | Operands | Stack Effect    | Description              |
|--------|------|----------|----------|-----------------|--------------------------|
| 16     | 0x10 | ADD      | —        | a b → (a+b)     | Integer addition         |
| 17     | 0x11 | SUB      | —        | a b → (a-b)     | Integer subtraction      |
| 18     | 0x12 | MUL      | —        | a b → (a*b)     | Integer multiplication   |
| 19     | 0x13 | DIV      | —        | a b → (a/b)     | Integer division (traps on /0) |
| 20     | 0x14 | MOD      | —        | a b → (a%b)     | Integer modulo           |
| 21     | 0x15 | EQ       | —        | a b → (a==b)    | Equality comparison      |
| 22     | 0x16 | NEQ      | —        | a b → (a!=b)    | Inequality               |
| 23     | 0x17 | LT       | —        | a b → (a<b)     | Less than                |
| 24     | 0x18 | GT       | —        | a b → (a>b)     | Greater than             |

### 3.4 Register Operations (0x20–0x2F)

| Opcode | Hex  | Mnemonic | Operands      | Stack Effect | Description                |
|--------|------|----------|---------------|--------------|----------------------------|
| 32     | 0x20 | SETREG   | reg: u8 (1B)  | val →        | Pop top, store in register |
| 33     | 0x21 | GETREG   | reg: u8 (1B)  | → val        | Push register value        |

### 3.5 Memory Operations (0x30–0x3F)

| Opcode | Hex  | Mnemonic | Operands | Stack Effect          | Description                         |
|--------|------|----------|----------|-----------------------|-------------------------------------|
| 48     | 0x30 | ALLOC    | —        | size → addr           | Allocate `size` bytes, push address |
| 49     | 0x31 | FREE     | —        | addr →                | Free allocated block                |
| 50     | 0x32 | MLOAD    | —        | addr len → bytes      | Load `len` bytes from address       |
| 51     | 0x33 | MSTORE   | —        | addr bytes →          | Store bytes at address              |

### 3.6 Cryptographic Operations (0x40–0x5F)

| Opcode | Hex  | Mnemonic      | Operands | Stack Effect              | Description                              |
|--------|------|---------------|----------|---------------------------|------------------------------------------|
| 64     | 0x40 | SHA256        | —        | data → hash               | SHA-256 hash of Bytes                    |
| 65     | 0x41 | SHA3_256      | —        | data → hash               | SHA3-256 hash of Bytes                   |
| 66     | 0x42 | HMAC          | —        | key_handle data → mac     | HMAC-SHA256 using key from key store     |
| 67     | 0x43 | AES_ENCRYPT   | —        | key_handle nonce data → ct| AES-256-GCM encrypt                      |
| 68     | 0x44 | AES_DECRYPT   | —        | key_handle nonce ct → pt  | AES-256-GCM decrypt                      |
| 69     | 0x45 | RSA_SIGN      | —        | key_handle data → sig     | RSA-PSS sign (2048-bit)                  |
| 70     | 0x46 | RSA_VERIFY    | —        | key_handle data sig → bool| RSA-PSS verify                           |
| 71     | 0x47 | ECDSA_SIGN    | —        | key_handle data → sig     | ECDSA-P256 sign                          |
| 72     | 0x48 | ECDSA_VERIFY  | —        | key_handle data sig → bool| ECDSA-P256 verify                        |
| 73     | 0x49 | RAND_BYTES    | —        | len → bytes               | Generate `len` cryptographically random bytes |
| 74     | 0x4A | GEN_SYM_KEY   | —        | → key_handle              | Generate AES-256 symmetric key           |
| 75     | 0x4B | GEN_RSA_KEY   | —        | → key_handle              | Generate RSA-2048 keypair                |
| 76     | 0x4C | GEN_EC_KEY    | —        | → key_handle              | Generate ECDSA-P256 keypair              |

### 3.7 I/O & Debug (0x60–0x6F)

| Opcode | Hex  | Mnemonic  | Operands | Stack Effect | Description                    |
|--------|------|-----------|----------|--------------|--------------------------------|
| 96     | 0x60 | PRINT     | —        | val →        | Print top value to stdout      |
| 97     | 0x61 | DEBUG     | —        | —            | Dump VM state (debug mode)     |

## 4. Error Codes

| Code | Name              | Condition                                      |
|------|-------------------|------------------------------------------------|
| E01  | StackUnderflow    | Pop/peek on empty stack                        |
| E02  | StackOverflow     | Stack exceeds 65536 entries                    |
| E03  | InvalidOpcode     | Decoded opcode byte has no mapping             |
| E04  | TypeMismatch      | Operand type doesn't match instruction need    |
| E05  | OutOfBounds       | Memory access outside allocated region         |
| E06  | DivisionByZero    | DIV or MOD with zero divisor                   |
| E07  | GasExhausted      | Step counter exceeded execution limit          |
| E08  | CryptoError       | Underlying crypto operation failed             |
| E09  | InvalidKeyHandle  | KeyHandle not found in key store               |
| E10  | InvalidRegister   | Register index > 7                             |
| E11  | InvalidBytecode   | Header validation failed (bad magic/version)   |

## 5. Assembly Syntax

```asm
; Comments start with semicolons
; Labels end with colons
; Registers are R0–R7

start:
    PUSH_INT 10          ; Push integer 10
    SETREG R0            ; Store in R0
    PUSH_BYTES "hello"   ; Push string as bytes
    SHA256               ; Hash the bytes
    PRINT                ; Print the hash
    HALT                 ; Stop

loop:
    GETREG R0            ; Get counter
    PUSH_INT 1
    SUB                  ; Decrement
    DUP
    SETREG R0            ; Save back
    JNZ loop             ; Loop if nonzero
    RET
```

## 6. Bytecode File Magic

All `.cvmb` files begin with:

```
43 56 4D 00   ; "CVM\0"
01 00         ; Version 1.0
00 00         ; Flags (reserved)
XX XX XX XX   ; Code section size (little-endian u32)
```
