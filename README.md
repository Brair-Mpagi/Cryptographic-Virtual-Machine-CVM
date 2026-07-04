# Cryptographic Virtual Machine (CVM)

A stack-based virtual machine whose instruction set treats cryptographic operations — hashing, symmetric encryption, asymmetric signatures, key derivation — as **first-class opcodes**, not library calls.

## Key Design Principles

- **Opaque Key Handles**: Raw key material never touches the operand stack. Keys exist only in the KeyStore and are referenced via opaque `KeyHandle` values. This prevents accidental key leakage.
- **Typed Value System**: Every stack/register value carries a type tag (`Int`, `Bytes`, `Bool`, `KeyHandle`). Type mismatches are trapped immediately.
- **Vetted Crypto Only**: All cryptographic primitives wrap battle-tested RustCrypto implementations. No hand-rolled crypto.
- **Sandboxed Execution**: Programs run within configurable resource envelopes (gas limits, instruction whitelists, memory quotas).

## Quick Start

```bash
# Build the project
cargo build --release

# Assemble an example program
cargo run --release --bin cvm -- asm examples/fibonacci.cvmasm -o fibonacci.cvmb

# Run it
cargo run --release --bin cvm -- run fibonacci.cvmb

# Disassemble to verify
cargo run --release --bin cvm -- disasm fibonacci.cvmb

# Run with gas limit (sandbox)
cargo run --release --bin cvm -- run fibonacci.cvmb --gas-limit 10000

# Debug mode (step trace)
cargo run --release --bin cvm -- debug fibonacci.cvmb
```

## Architecture

```
vm-cli ──┬── vm-asm        (assembler: .cvmasm → .cvmb)
         ├── vm-disasm     (disassembler: .cvmb → readable)
         ├── vm-crypto     (crypto opcode dispatch + key store)
         ├── vm-sandbox    (gas limits, instruction policies)
         └── vm-core       (stack, registers, memory, execution loop)
```

See [docs/architecture.md](docs/architecture.md) for detailed component diagrams.

## Instruction Set

The CVM ISA includes ~35 opcodes across 6 categories:

| Category       | Opcodes                                                        |
|----------------|----------------------------------------------------------------|
| Stack/Control  | HALT, NOP, PUSH_INT, PUSH_BYTES, PUSH_BOOL, POP, DUP, SWAP, JMP, JZ, JNZ, CALL, RET |
| Arithmetic     | ADD, SUB, MUL, DIV, MOD, EQ, NEQ, LT, GT                     |
| Register       | SETREG, GETREG (R0–R7)                                        |
| Memory         | ALLOC, FREE, MLOAD, MSTORE                                    |
| Crypto         | SHA256, SHA3_256, HMAC, AES_ENCRYPT, AES_DECRYPT, RSA_SIGN, RSA_VERIFY, ECDSA_SIGN, ECDSA_VERIFY, RAND_BYTES, GEN_SYM_KEY, GEN_RSA_KEY, GEN_EC_KEY |
| I/O            | PRINT, DEBUG                                                   |

See [docs/isa-spec.md](docs/isa-spec.md) for the complete specification.

## Example Programs

| File | Description |
|------|-------------|
| `fibonacci.cvmasm` | Iterative Fibonacci using registers and loops |
| `factorial.cvmasm` | Factorial with CALL/RET subroutines |
| `hash-and-sign.cvmasm` | SHA256 → ECDSA sign → verify roundtrip |
| `sandbox-escape-attempt.cvmasm` | Infinite loop (killed by gas limit) |

## Testing

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p cvm-core
cargo test -p cvm-crypto
cargo test -p cvm-asm
```

## Project Structure

```
cvm/
├── docs/                 # ISA spec and architecture docs
├── crates/
│   ├── vm-core/          # Stack, registers, memory, execution loop
│   ├── vm-crypto/        # Crypto provider + key store + dispatch
│   ├── vm-asm/           # Assembler (lexer → parser → emitter)
│   ├── vm-disasm/        # Disassembler
│   ├── vm-sandbox/       # Gas limits, instruction policies
│   └── vm-cli/           # CLI binary (cvm)
├── examples/             # Example .cvmasm programs
├── tests/                # Integration tests
└── benches/              # Benchmarks
```

## What This Demonstrates

- **Compiler/Language Implementation**: Full lexer → parser → bytecode pipeline
- **Systems Programming**: Low-level VM with manual memory management
- **Applied Cryptography Engineering**: Correct use of vetted primitives
- **Security-Minded API Design**: Opaque key handles prevent key leakage
- **Sandboxing/Isolation**: Resource-limited execution environments

## License

MIT
