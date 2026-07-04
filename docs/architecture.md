# CVM Architecture

## System Overview

```
                    ┌────────────────────┐
   source (.cvmasm) │      Assembler      │  →  bytecode (.cvmb)
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │     Loader          │  validates header, checks ISA version
                    └─────────┬──────────┘
                              │
  ┌───────────────────────────▼───────────────────────────┐
  │                        VM Core                         │
  │  ┌───────────┐ ┌───────────┐ ┌────────────────────┐   │
  │  │  Fetch    │→│  Decode   │→│      Execute        │   │
  │  └───────────┘ └───────────┘ └────────┬───────────┘   │
  │                                        │               │
  │   ┌───────────┐  ┌───────────┐  ┌──────▼───────┐      │
  │   │  Stack    │  │ Registers │  │ Crypto Opcode │      │
  │   │           │  │  (R0–R7)  │  │   Dispatch    │      │
  │   └───────────┘  └───────────┘  └───────┬───────┘      │
  │                                          │              │
  │                              ┌───────────▼──────────┐   │
  │                              │  Crypto Provider      │   │
  │                              │ (wraps RustCrypto)    │   │
  │                              └──────────────────────┘   │
  │   ┌────────────────────┐  ┌─────────────────────────┐   │
  │   │  Sandbox Policy    │  │   Memory Manager (heap) │   │
  │   │  (gas, whitelist)  │  │                         │   │
  │   └────────────────────┘  └─────────────────────────┘   │
  └─────────────────────────────────────────────────────────┘
```

## Crate Dependency Graph

```
vm-cli ──┬── vm-asm
         ├── vm-disasm
         ├── vm-crypto ── vm-core
         ├── vm-sandbox ── vm-core
         └── vm-core
```

## Component Responsibilities

### vm-core
- Opcode definition and encoding/decoding
- Typed value system (Int, Bytes, Bool, KeyHandle)
- Operand stack with type-safe operations
- Register file (R0–R7)
- Heap memory manager with allocation tracking
- Fetch-decode-execute main loop
- Error/trap system

### vm-crypto
- `CryptoProvider` trait abstracting all crypto operations
- `RustCryptoProvider` implementation using sha2, sha3, aes-gcm, rsa, p256
- `KeyStore` mapping opaque handles to actual key material
- Crypto opcode dispatch (validates types, calls provider, pushes results)

### vm-asm
- Lexer: tokenizes `.cvmasm` source files
- Parser: two-pass assembly (pass 1: collect labels, pass 2: resolve + emit)
- Emitter: produces `.cvmb` bytecode files with proper header

### vm-disasm
- Parses `.cvmb` file header
- Iterates code section, decodes each instruction
- Renders human-readable assembly with addresses

### vm-sandbox
- Gas/step counter with configurable limits
- Per-opcode cost model (crypto ops > arithmetic > stack ops)
- Instruction whitelist/blacklist policies
- Memory quota enforcement

### vm-cli
- `cvm run` — execute bytecode
- `cvm asm` — assemble source to bytecode
- `cvm disasm` — disassemble bytecode
- `cvm debug` — step-through execution with state dumps

## Security Design

1. **Opaque Key Handles**: Keys exist only in the KeyStore. The stack never contains raw key bytes.
2. **Typed Stack**: Type mismatches are caught at execution time (and optionally at load time).
3. **Sandboxing**: Programs execute within configurable resource envelopes.
4. **No raw crypto**: All cryptographic operations use vetted library implementations.
