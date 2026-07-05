// CVM JavaScript Assembler and Execution Simulator

// -------------------------------------------------------------
// Opcodes & Instruction Set Definition
// -------------------------------------------------------------
const OPCODES = {
    NOP:          { code: 0x00, gas: 1,   mnemonic: "NOP" },
    HALT:         { code: 0x01, gas: 1,   mnemonic: "HALT" },
    PUSH_INT:     { code: 0x02, gas: 2,   mnemonic: "PUSH_INT" },
    PUSH_BYTES:   { code: 0x03, gas: 4,   mnemonic: "PUSH_BYTES" },
    PUSH_BOOL:    { code: 0x04, gas: 2,   mnemonic: "PUSH_BOOL" },
    POP:          { code: 0x05, gas: 2,   mnemonic: "POP" },
    DUP:          { code: 0x06, gas: 2,   mnemonic: "DUP" },
    SWAP:         { code: 0x07, gas: 2,   mnemonic: "SWAP" },
    
    ADD:          { code: 0x10, gas: 3,   mnemonic: "ADD" },
    SUB:          { code: 0x11, gas: 3,   mnemonic: "SUB" },
    MUL:          { code: 0x12, gas: 4,   mnemonic: "MUL" },
    DIV:          { code: 0x13, gas: 4,   mnemonic: "DIV" },
    MOD:          { code: 0x14, gas: 4,   mnemonic: "MOD" },
    EQ:           { code: 0x15, gas: 3,   mnemonic: "EQ" },
    NEQ:          { code: 0x16, gas: 3,   mnemonic: "NEQ" },
    LT:           { code: 0x17, gas: 3,   mnemonic: "LT" },
    GT:           { code: 0x18, gas: 3,   mnemonic: "GT" },
    
    JMP:          { code: 0x20, gas: 3,   mnemonic: "JMP" },
    JZ:           { code: 0x21, gas: 4,   mnemonic: "JZ" },
    JNZ:          { code: 0x22, gas: 4,   mnemonic: "JNZ" },
    CALL:         { code: 0x23, gas: 5,   mnemonic: "CALL" },
    RET:          { code: 0x24, gas: 5,   mnemonic: "RET" },
    
    SETREG:       { code: 0x30, gas: 2,   mnemonic: "SETREG" },
    GETREG:       { code: 0x31, gas: 2,   mnemonic: "GETREG" },
    
    ALLOC:        { code: 0x40, gas: 10,  mnemonic: "ALLOC" },
    FREE:         { code: 0x41, gas: 10,  mnemonic: "FREE" },
    MLOAD:        { code: 0x42, gas: 5,   mnemonic: "MLOAD" },
    MSTORE:       { code: 0x43, gas: 5,   mnemonic: "MSTORE" },
    
    SHA256:       { code: 0x50, gas: 30,  mnemonic: "SHA256" },
    SHA3_256:     { code: 0x51, gas: 35,  mnemonic: "SHA3_256" },
    HMAC:         { code: 0x52, gas: 40,  mnemonic: "HMAC" },
    AES_ENCRYPT:  { code: 0x53, gas: 50,  mnemonic: "AES_ENCRYPT" },
    AES_DECRYPT:  { code: 0x54, gas: 50,  mnemonic: "AES_DECRYPT" },
    RSA_SIGN:     { code: 0x55, gas: 200, mnemonic: "RSA_SIGN" },
    RSA_VERIFY:   { code: 0x56, gas: 150, mnemonic: "RSA_VERIFY" },
    ECDSA_SIGN:   { code: 0x57, gas: 100, mnemonic: "ECDSA_SIGN" },
    ECDSA_VERIFY: { code: 0x58, gas: 80,  mnemonic: "ECDSA_VERIFY" },
    RAND_BYTES:   { code: 0x59, gas: 15,  mnemonic: "RAND_BYTES" },
    GEN_SYM_KEY:  { code: 0x5A, gas: 80,  mnemonic: "GEN_SYM_KEY" },
    GEN_RSA_KEY:  { code: 0x5B, gas: 500, mnemonic: "GEN_RSA_KEY" },
    GEN_EC_KEY:   { code: 0x5C, gas: 150, mnemonic: "GEN_EC_KEY" },
    
    PRINT:        { code: 0x60, gas: 5,   mnemonic: "PRINT" },
    DEBUG:        { code: 0x61, gas: 2,   mnemonic: "DEBUG" }
};

// Quick map of opcode byte to metadata
const OP_BY_BYTE = {};
Object.entries(OPCODES).forEach(([k, v]) => {
    OP_BY_BYTE[v.code] = v;
});

// -------------------------------------------------------------
// Program Templates
// -------------------------------------------------------------
const TEMPLATES = {
    fibonacci: `; Fibonacci Calculator
; Computes the 10th Fibonacci number
; Registers: R0=N, R1=fib(n-1), R2=fib(n)

    PUSH_INT 10
    SETREG R0

    PUSH_INT 0
    SETREG R1
    PUSH_INT 1
    SETREG R2

loop:
    GETREG R0
    PUSH_INT 0
    EQ
    JNZ done

    GETREG R2      ; temp = R2
    
    GETREG R1
    GETREG R2
    ADD
    SETREG R2      ; R2 = R1 + R2

    SETREG R1      ; R1 = temp

    GETREG R0
    PUSH_INT 1
    SUB
    SETREG R0      ; N = N - 1

    JMP loop

done:
    GETREG R2
    PRINT
    HALT
`,

    factorial: `; Subroutine Factorial
; Computes 7! (5040) using CALL/RET
; Registers: R0=N, R1=accum

    PUSH_INT 7
    SETREG R0

    CALL factorial
    PRINT
    HALT

factorial:
    PUSH_INT 1
    SETREG R1

fact_loop:
    GETREG R0
    PUSH_INT 1
    GT
    JZ fact_done

    GETREG R1
    GETREG R0
    MUL
    SETREG R1

    GETREG R0
    PUSH_INT 1
    SUB
    SETREG R0

    JMP fact_loop

fact_done:
    GETREG R1
    RET
`,

    crypto: `; Cryptographic Hash & Sign
; Demonstrates SHA256, key generation, ECDSA sign & verify
; Keys are handles (opaque integers)

    ; Step 1: Generate ECDSA Keypair
    GEN_EC_KEY
    SETREG R0

    ; Step 2: Push input data
    PUSH_BYTES "Hello, Cryptographic Virtual Machine!"

    ; Step 3: SHA256 Hash
    SHA256
    DUP
    SETREG R1

    ; Step 4: Sign hash
    GETREG R0
    GETREG R1
    ECDSA_SIGN
    SETREG R2

    ; Step 5: Verify signature
    GETREG R0
    GETREG R1
    GETREG R2
    ECDSA_VERIFY

    PRINT
    HALT
`,

    sandbox: `; Sandbox Escape (Infinite Loop)
; Run this with a gas limit to watch the sandbox abort

    PUSH_INT 0
    SETREG R0

infinite:
    GETREG R0
    PUSH_INT 1
    ADD
    DUP
    SETREG R0

    JMP infinite
    HALT
`
};

// -------------------------------------------------------------
// Core CVM Assembler
// -------------------------------------------------------------
class Assembler {
    static assemble(source) {
        const lines = source.split('\n');
        const labels = {};
        const instructions = [];
        let currentOffset = 0;

        // Pass 1: Parse structure and resolve label offsets
        for (let i = 0; i < lines.length; i++) {
            let line = lines[i].trim();
            // Remove comments
            const commentIdx = line.indexOf(';');
            if (commentIdx !== -1) {
                line = line.substring(0, commentIdx).trim();
            }
            if (!line) continue;

            // Check for label definition
            if (line.endsWith(':')) {
                const labelName = line.substring(0, line.length - 1).trim();
                if (labels[labelName] !== undefined) {
                    throw new Error(`Line ${i + 1}: Label '${labelName}' redefined`);
                }
                labels[labelName] = currentOffset;
                continue;
            }

            // Parse mnemonic and operands
            const parts = line.split(/\s+/);
            const mnemonic = parts[0].toUpperCase();
            const opInfo = OPCODES[mnemonic];
            if (!opInfo) {
                throw new Error(`Line ${i + 1}: Unknown opcode '${mnemonic}'`);
            }

            const operandsRaw = parts.slice(1).join(' ').trim();
            let size = 1; // 1 byte for opcode

            if (opInfo.mnemonic === "PUSH_INT") {
                size += 8; // 64-bit int
            } else if (opInfo.mnemonic === "PUSH_BOOL") {
                size += 1; // 1 byte boolean
            } else if (opInfo.mnemonic === "PUSH_BYTES") {
                // Parse string literal
                if (!operandsRaw.startsWith('"') || !operandsRaw.endsWith('"')) {
                    throw new Error(`Line ${i + 1}: PUSH_BYTES requires string literal in quotes`);
                }
                const content = operandsRaw.substring(1, operandsRaw.length - 1);
                size += 2 + content.length; // 2 bytes length + data bytes
            } else if (["JMP", "JZ", "JNZ", "CALL"].includes(opInfo.mnemonic)) {
                size += 4; // 32-bit address offset
            } else if (["SETREG", "GETREG"].includes(opInfo.mnemonic)) {
                size += 1; // register index byte
            }

            instructions.push({
                lineNum: i + 1,
                mnemonic,
                opcode: opInfo.code,
                operandsRaw,
                offset: currentOffset,
                size
            });

            currentOffset += size;
        }

        // Pass 2: Generate bytecode and resolve targets
        const bytecode = new Uint8Array(12 + currentOffset);
        
        // 1. Magic Bytes: "CVM\0"
        bytecode[0] = 0x43;
        bytecode[1] = 0x56;
        bytecode[2] = 0x4D;
        bytecode[3] = 0x00;
        
        // 2. Version: Major 1 (byte 4), Minor 0 (byte 5)
        bytecode[4] = 1;
        bytecode[5] = 0;
        
        // 3. Section count (unused in visualizer, but matches Rust layout)
        bytecode[6] = 1;
        bytecode[7] = 0;
        
        // 4. Code size: 32-bit LE int (bytes 8-11)
        bytecode[8] = currentOffset & 0xFF;
        bytecode[9] = (currentOffset >> 8) & 0xFF;
        bytecode[10] = (currentOffset >> 16) & 0xFF;
        bytecode[11] = (currentOffset >> 24) & 0xFF;

        let pc = 12; // Start writing code section

        for (const inst of instructions) {
            bytecode[pc++] = inst.opcode;

            if (inst.mnemonic === "PUSH_INT") {
                const val = parseInt(inst.operandsRaw, 10);
                if (isNaN(val)) throw new Error(`Line ${inst.lineNum}: Invalid integer operand '${inst.operandsRaw}'`);
                // Write 64-bit LE integer
                let temp = BigInt(val);
                for (let b = 0; b < 8; b++) {
                    bytecode[pc++] = Number(temp & 0xFFn);
                    temp >>= 8n;
                }
            } else if (inst.mnemonic === "PUSH_BOOL") {
                const val = inst.operandsRaw.toLowerCase() === "true" ? 1 : 0;
                bytecode[pc++] = val;
            } else if (inst.mnemonic === "PUSH_BYTES") {
                const content = inst.operandsRaw.substring(1, inst.operandsRaw.length - 1);
                // 16-bit LE string length
                const len = content.length;
                bytecode[pc++] = len & 0xFF;
                bytecode[pc++] = (len >> 8) & 0xFF;
                // Characters
                for (let c = 0; c < len; c++) {
                    bytecode[pc++] = content.charCodeAt(c);
                }
            } else if (["JMP", "JZ", "JNZ", "CALL"].includes(inst.mnemonic)) {
                // Resolve target label address
                const targetLabel = inst.operandsRaw;
                const targetOffset = labels[targetLabel];
                if (targetOffset === undefined) {
                    throw new Error(`Line ${inst.lineNum}: Undefined label target '${targetLabel}'`);
                }
                // Write 32-bit LE target address
                bytecode[pc++] = targetOffset & 0xFF;
                bytecode[pc++] = (targetOffset >> 8) & 0xFF;
                bytecode[pc++] = (targetOffset >> 16) & 0xFF;
                bytecode[pc++] = (targetOffset >> 24) & 0xFF;
            } else if (["SETREG", "GETREG"].includes(inst.mnemonic)) {
                const regStr = inst.operandsRaw.toUpperCase();
                if (!regStr.startsWith("R")) throw new Error(`Line ${inst.lineNum}: Expected register (R0-R7)`);
                const regIdx = parseInt(regStr.substring(1), 10);
                if (isNaN(regIdx) || regIdx < 0 || regIdx > 7) {
                    throw new Error(`Line ${inst.lineNum}: Invalid register index '${regStr}'`);
                }
                bytecode[pc++] = regIdx;
            }
        }

        return bytecode;
    }
}

// -------------------------------------------------------------
// CVM Virtual Machine Simulator
// -------------------------------------------------------------
class VirtualMachine {
    constructor(bytecode, gasLimit) {
        this.bytecode = bytecode;
        this.gasLimit = gasLimit;
        
        // Parse Header
        this.codeSize = bytecode[8] | (bytecode[9] << 8) | (bytecode[10] << 16) | (bytecode[11] << 24);
        this.code = bytecode.slice(12, 12 + this.codeSize);

        // Core States
        this.pc = 0;
        this.stack = [];
        this.registers = Array(8).fill(null).map(() => ({ type: "Empty", value: null }));
        this.keystore = new Map();
        this.nextKeyId = 1;
        this.callStack = [];

        // Execution Stats
        this.steps = 0;
        this.gasConsumed = 0;
        this.status = "READY"; // READY, RUNNING, HALTED, ERROR
        this.errorMsg = null;
        this.logs = [];
    }

    addLog(msg, type = "system") {
        this.logs.push({ msg, type });
        if (this.onLog) this.onLog(msg, type);
    }

    // Single instruction step
    step() {
        if (this.status === "HALTED" || this.status === "ERROR") return false;
        
        if (this.pc >= this.code.length) {
            this.status = "ERROR";
            this.errorMsg = "Program counter out of bounds";
            this.addLog("Trap: PC out of bounds", "error");
            return false;
        }

        const currentPc = this.pc;
        const opByte = this.code[this.pc++];
        const opInfo = OP_BY_BYTE[opByte];

        if (!opInfo) {
            this.status = "ERROR";
            this.errorMsg = `Unknown opcode 0x${opByte.toString(16).toUpperCase()}`;
            this.addLog(`Trap: Unknown opcode 0x${opByte.toString(16).toUpperCase()}`, "error");
            return false;
        }

        // Apply Gas
        this.gasConsumed += opInfo.gas;
        if (this.gasConsumed > this.gasLimit) {
            this.status = "ERROR";
            this.errorMsg = `Gas Limit Exceeded`;
            this.addLog(`Trap: E07 GasExhausted (limit: ${this.gasLimit})`, "error");
            return false;
        }

        this.steps++;

        try {
            this.executeOp(opInfo, currentPc);
        } catch (e) {
            this.status = "ERROR";
            this.errorMsg = e.message;
            this.addLog(`Trap: ${e.message}`, "error");
            return false;
        }

        return this.status !== "HALTED" && this.status !== "ERROR";
    }

    executeOp(op, instructionPc) {
        let traceDetail = `0x${instructionPc.toString(16).toUpperCase().padStart(4, '0')}: ${op.mnemonic}`;

        switch (op.mnemonic) {
            case "NOP":
                break;
                
            case "HALT":
                this.status = "HALTED";
                this.addLog("Program HALT reached.", "system");
                break;

            case "PUSH_INT": {
                // Read 64-bit LE int
                let val = 0n;
                for (let i = 0; i < 8; i++) {
                    val |= BigInt(this.code[this.pc++]) << BigInt(i * 8);
                }
                // Handle signed 64-bit value
                if (val >= 0x8000000000000000n) {
                    val -= 0x10000000000000000n;
                }
                const num = Number(val);
                this.stack.push({ type: "int", value: num });
                traceDetail += ` ${num}`;
                break;
            }

            case "PUSH_BOOL": {
                const val = this.code[this.pc++] !== 0;
                this.stack.push({ type: "bool", value: val });
                traceDetail += ` ${val}`;
                break;
            }

            case "PUSH_BYTES": {
                const len = this.code[this.pc++] | (this.code[this.pc++] << 8);
                let chars = "";
                for (let i = 0; i < len; i++) {
                    chars += String.fromCharCode(this.code[this.pc++]);
                }
                this.stack.push({ type: "bytes", value: chars });
                traceDetail += ` "${chars}"`;
                break;
            }

            case "POP":
                if (this.stack.length === 0) throw new Error("E01 StackUnderflow");
                this.stack.pop();
                break;

            case "DUP": {
                if (this.stack.length === 0) throw new Error("E01 StackUnderflow");
                const top = this.stack[this.stack.length - 1];
                this.stack.push({ ...top });
                break;
            }

            case "SWAP": {
                if (this.stack.length < 2) throw new Error("E01 StackUnderflow");
                const first = this.stack.pop();
                const second = this.stack.pop();
                this.stack.push(first);
                this.stack.push(second);
                break;
            }

            case "ADD": {
                const b = this.popInt();
                const a = this.popInt();
                this.stack.push({ type: "int", value: a + b });
                break;
            }

            case "SUB": {
                const b = this.popInt();
                const a = this.popInt();
                this.stack.push({ type: "int", value: a - b });
                break;
            }

            case "MUL": {
                const b = this.popInt();
                const a = this.popInt();
                this.stack.push({ type: "int", value: a * b });
                break;
            }

            case "DIV": {
                const b = this.popInt();
                const a = this.popInt();
                if (b === 0) throw new Error("E05 DivisionByZero");
                this.stack.push({ type: "int", value: Math.floor(a / b) });
                break;
            }

            case "MOD": {
                const b = this.popInt();
                const a = this.popInt();
                if (b === 0) throw new Error("E05 DivisionByZero");
                this.stack.push({ type: "int", value: a % b });
                break;
            }

            case "EQ": {
                const b = this.stack.pop();
                const a = this.stack.pop();
                if (!a || !b) throw new Error("E01 StackUnderflow");
                this.stack.push({ type: "bool", value: a.value === b.value && a.type === b.type });
                break;
            }

            case "NEQ": {
                const b = this.stack.pop();
                const a = this.stack.pop();
                if (!a || !b) throw new Error("E01 StackUnderflow");
                this.stack.push({ type: "bool", value: a.value !== b.value || a.type !== b.type });
                break;
            }

            case "LT": {
                const b = this.popInt();
                const a = this.popInt();
                this.stack.push({ type: "bool", value: a < b });
                break;
            }

            case "GT": {
                const b = this.popInt();
                const a = this.popInt();
                this.stack.push({ type: "bool", value: a > b });
                break;
            }

            case "SETREG": {
                const reg = this.code[this.pc++];
                if (this.stack.length === 0) throw new Error("E01 StackUnderflow");
                this.registers[reg] = this.stack.pop();
                traceDetail += ` R${reg}`;
                break;
            }

            case "GETREG": {
                const reg = this.code[this.pc++];
                const val = this.registers[reg];
                if (val.type === "Empty") throw new Error(`Access to uninitialized Register R${reg}`);
                this.stack.push({ ...val });
                traceDetail += ` R${reg}`;
                break;
            }

            case "JMP": {
                const target = this.readAddr32();
                this.pc = target;
                traceDetail += ` 0x${target.toString(16).toUpperCase().padStart(4, '0')}`;
                break;
            }

            case "JZ": {
                const target = this.readAddr32();
                const cond = this.popBool();
                if (!cond) {
                    this.pc = target;
                }
                traceDetail += ` 0x${target.toString(16).toUpperCase().padStart(4, '0')}`;
                break;
            }

            case "JNZ": {
                const target = this.readAddr32();
                const cond = this.popBool();
                if (cond) {
                    this.pc = target;
                }
                traceDetail += ` 0x${target.toString(16).toUpperCase().padStart(4, '0')}`;
                break;
            }

            case "CALL": {
                const target = this.readAddr32();
                this.callStack.push(this.pc);
                this.pc = target;
                traceDetail += ` 0x${target.toString(16).toUpperCase().padStart(4, '0')}`;
                break;
            }

            case "RET":
                if (this.callStack.length === 0) throw new Error("Call stack underflow on RET instruction");
                this.pc = this.callStack.pop();
                break;

            // --- Cryptography Primitives ---
            case "GEN_EC_KEY": {
                const kid = this.nextKeyId++;
                this.keystore.set(kid, { type: "ECDSA-P256", details: "sec1_public_der / dsa_private" });
                this.stack.push({ type: "keyhandle", value: kid });
                this.addLog(`Keystore: Generated ECDSA-P256 Keypair (Handle ${kid})`);
                break;
            }

            case "GEN_SYM_KEY": {
                const kid = this.nextKeyId++;
                this.keystore.set(kid, { type: "AES-256", details: "symmetric_key_32_bytes" });
                this.stack.push({ type: "keyhandle", value: kid });
                this.addLog(`Keystore: Generated AES-256 Key (Handle ${kid})`);
                break;
            }

            case "GEN_RSA_KEY": {
                const kid = this.nextKeyId++;
                this.keystore.set(kid, { type: "RSA-2048", details: "rsa_pkcs8_der" });
                this.stack.push({ type: "keyhandle", value: kid });
                this.addLog(`Keystore: Generated RSA-2048 Keypair (Handle ${kid})`);
                break;
            }

            case "SHA256": {
                const data = this.popBytes();
                // Simple deterministic mock hash
                const hash = this.sha256Mock(data);
                this.stack.push({ type: "bytes", value: hash });
                break;
            }

            case "ECDSA_SIGN": {
                const hash = this.popBytes();
                const keyHandle = this.popKeyHandle();
                const key = this.keystore.get(keyHandle);
                if (!key || key.type !== "ECDSA-P256") throw new Error("E08 InvalidKeyHandle / Type Mismatch");
                
                const signature = `ecdsa_sig_of_${hash.substring(0, 10)}_by_handle_${keyHandle}`;
                this.stack.push({ type: "bytes", value: signature });
                break;
            }

            case "ECDSA_VERIFY": {
                const sig = this.popBytes();
                const hash = this.popBytes();
                const keyHandle = this.popKeyHandle();
                const key = this.keystore.get(keyHandle);
                if (!key || key.type !== "ECDSA-P256") throw new Error("E08 InvalidKeyHandle / Type Mismatch");

                const expectedSig = `ecdsa_sig_of_${hash.substring(0, 10)}_by_handle_${keyHandle}`;
                const isValid = sig === expectedSig;
                this.stack.push({ type: "bool", value: isValid });
                break;
            }

            case "PRINT": {
                if (this.stack.length === 0) throw new Error("E01 StackUnderflow");
                const val = this.stack.pop();
                this.addLog(`[STDOUT] ${val.value}`, "output");
                break;
            }

            default:
                throw new Error(`Instruction ${op.mnemonic} execution details missing in simulation`);
        }

        // Trace line
        this.addLog(traceDetail, "trace");
    }

    // Helper Type Stack Extractors
    popInt() {
        const item = this.stack.pop();
        if (!item) throw new Error("E01 StackUnderflow");
        if (item.type !== "int") throw new Error(`E03 TypeMismatch: Expected int, got ${item.type}`);
        return item.value;
    }

    popBool() {
        const item = this.stack.pop();
        if (!item) throw new Error("E01 StackUnderflow");
        if (item.type !== "bool") throw new Error(`E03 TypeMismatch: Expected bool, got ${item.type}`);
        return item.value;
    }

    popBytes() {
        const item = this.stack.pop();
        if (!item) throw new Error("E01 StackUnderflow");
        if (item.type !== "bytes") throw new Error(`E03 TypeMismatch: Expected bytes, got ${item.type}`);
        return item.value;
    }

    popKeyHandle() {
        const item = this.stack.pop();
        if (!item) throw new Error("E01 StackUnderflow");
        if (item.type !== "keyhandle") throw new Error(`E03 TypeMismatch: Expected keyhandle, got ${item.type}`);
        return item.value;
    }

    readAddr32() {
        return this.code[this.pc++] | (this.code[this.pc++] << 8) | (this.code[this.pc++] << 16) | (this.code[this.pc++] << 24);
    }

    sha256Mock(str) {
        // Simple deterministic hash mapping for simulator
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = (hash << 5) - hash + str.charCodeAt(i);
            hash |= 0;
        }
        return "hash_" + Math.abs(hash).toString(16).padStart(8, '0') + "c48477c9613b45f89f16467d";
    }
}

// -------------------------------------------------------------
// UI Bindings & Application Logic
// -------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
    const editor = document.getElementById("code-editor");
    const lineNumbers = document.getElementById("line-numbers");
    const templateSelect = document.getElementById("template-select");
    const gasLimitInput = document.getElementById("gas-limit-input");
    const bytecodeView = document.getElementById("bytecode-view");
    const bytecodeSize = document.getElementById("bytecode-size");
    const consoleView = document.getElementById("console-view");
    
    // Internal values
    const btnAssemble = document.getElementById("btn-assemble");
    const btnRun = document.getElementById("btn-run");
    const btnStep = document.getElementById("btn-step");
    const btnReset = document.getElementById("btn-reset");
    const btnClearConsole = document.getElementById("btn-clear-console");

    // Internals Views
    const statSteps = document.getElementById("stat-steps");
    const statGas = document.getElementById("stat-gas");
    const gasProgress = document.getElementById("gas-progress");
    const valPc = document.getElementById("val-pc");
    const valOpcode = document.getElementById("val-opcode");
    const stackView = document.getElementById("stack-view");
    const stackCount = document.getElementById("stack-count");
    const registersView = document.getElementById("registers-view");
    const keystoreView = document.getElementById("keystore-view");
    const keystoreCount = document.getElementById("keystore-count");
    const vmRunStatus = document.getElementById("vm-run-status");

    let currentBytecode = null;
    let vm = null;

    // Load templates
    editor.value = TEMPLATES.fibonacci;
    updateLineNumbers();

    templateSelect.addEventListener("change", (e) => {
        editor.value = TEMPLATES[e.target.value];
        updateLineNumbers();
        resetVM();
    });

    editor.addEventListener("input", updateLineNumbers);
    editor.addEventListener("scroll", () => {
        lineNumbers.scrollTop = editor.scrollTop;
    });

    function updateLineNumbers() {
        const lines = editor.value.split('\n').length;
        let numHtml = "";
        for (let i = 1; i <= lines; i++) {
            numHtml += `<div>${i}</div>`;
        }
        lineNumbers.innerHTML = numHtml;
    }

    btnClearConsole.addEventListener("click", () => {
        consoleView.innerHTML = "";
    });

    // Assemble action
    btnAssemble.addEventListener("click", () => {
        try {
            const bytecode = Assembler.assemble(editor.value);
            currentBytecode = bytecode;
            
            // Render Bytecode Hex
            let hex = "";
            for (let i = 0; i < bytecode.length; i++) {
                hex += bytecode[i].toString(16).padStart(2, '0').toUpperCase() + " ";
            }
            bytecodeView.innerHTML = `<div class="bytecode-hex">${hex}</div>`;
            bytecodeSize.innerText = `${bytecode.length} bytes`;

            addConsoleLog("Assembly Successful! Code compiled.", "system");
            
            // Enable VM runner
            btnRun.disabled = false;
            btnStep.disabled = false;

            // Initialize VM
            resetVM();
        } catch (e) {
            addConsoleLog(`Assembly Error: ${e.message}`, "error");
            bytecodeView.innerHTML = `<div class="empty-state error" style="color:var(--red)">Assembly failed.</div>`;
            bytecodeSize.innerText = "0 bytes";
            btnRun.disabled = true;
            btnStep.disabled = true;
        }
    });

    function addConsoleLog(msg, type) {
        const line = document.createElement("div");
        line.className = `console-line ${type}`;
        line.innerText = msg;
        consoleView.appendChild(line);
        consoleView.scrollTop = consoleView.scrollHeight;
    }

    function resetVM() {
        if (!currentBytecode) return;
        const gasLimit = parseInt(gasLimitInput.value, 10) || 1000;
        vm = new VirtualMachine(currentBytecode, gasLimit);
        vm.onLog = (msg, type) => {
            addConsoleLog(msg, type);
        };
        updateInternalUi();
    }

    btnReset.addEventListener("click", () => {
        resetVM();
        addConsoleLog("Virtual Machine Reset.", "system");
    });

    // Run action
    btnRun.addEventListener("click", () => {
        if (!vm) return;
        vm.status = "RUNNING";
        addConsoleLog("Executing program...", "system");
        
        let running = true;
        while (running) {
            running = vm.step();
        }
        updateInternalUi();
    });

    // Step action
    btnStep.addEventListener("click", () => {
        if (!vm) return;
        vm.status = "RUNNING";
        vm.step();
        updateInternalUi();
    });

    function updateInternalUi() {
        if (!vm) return;

        // Stats
        statSteps.innerText = vm.steps;
        statGas.innerText = `${vm.gasConsumed} / ${vm.gasLimit}`;
        const pct = Math.min(100, (vm.gasConsumed / vm.gasLimit) * 100);
        gasProgress.style.width = `${pct}%`;
        if (pct > 90) gasProgress.style.background = "var(--red)";
        else if (pct > 60) gasProgress.style.background = "var(--orange)";
        else gasProgress.style.background = "var(--gradient-primary)";

        // Run status badge
        vmRunStatus.className = `run-status ${vm.status.toLowerCase()}`;
        vmRunStatus.innerText = vm.status;

        // PC & Opcode
        valPc.innerText = `0x${vm.pc.toString(16).toUpperCase().padStart(4, '0')}`;
        
        const nextOpByte = vm.code[vm.pc];
        const op = OP_BY_BYTE[nextOpByte];
        valOpcode.innerText = op ? op.mnemonic : (nextOpByte !== undefined ? `0x${nextOpByte.toString(16).toUpperCase()}` : "HALT");

        // Stack
        stackCount.innerText = vm.stack.length;
        if (vm.stack.length === 0) {
            stackView.innerHTML = `<div class="empty-state">Stack is empty</div>`;
        } else {
            stackView.innerHTML = vm.stack.map((item, idx) => `
                <div class="stack-item">
                    <span>[${idx}] <strong>${item.value}</strong></span>
                    <span class="type-tag ${item.type}">${item.type}</span>
                </div>
            `).join('');
        }

        // Registers
        registersView.innerHTML = vm.registers.map((reg, idx) => `
            <div class="register-cell ${reg.type !== "Empty" ? "active" : ""}">
                <span class="reg-name">R${idx}</span>
                <span class="reg-val ${reg.type === "Empty" ? "empty" : ""}" title="${reg.value}">
                    ${reg.type === "Empty" ? "-" : reg.value}
                </span>
            </div>
        `).join('');

        // Keystore
        keystoreCount.innerText = vm.keystore.size;
        if (vm.keystore.size === 0) {
            keystoreView.innerHTML = `<div class="empty-state">No keys generated</div>`;
        } else {
            let html = "";
            vm.keystore.forEach((val, key) => {
                html += `
                    <div class="key-item">
                        <span class="key-id">Handle ${key}</span>
                        <span class="key-info">${val.type}</span>
                    </div>
                `;
            });
            keystoreView.innerHTML = html;
        }

        // Button state handling
        if (vm.status === "HALTED" || vm.status === "ERROR") {
            btnRun.disabled = true;
            btnStep.disabled = true;
        } else {
            btnRun.disabled = false;
            btnStep.disabled = false;
        }
    }
});