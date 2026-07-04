// CVM CLI — Command-line interface for the Cryptographic Virtual Machine
//
// Commands:
//   cvm run <file.cvmb>              Execute bytecode
//   cvm asm <file.cvmasm> -o <out>   Assemble source to bytecode
//   cvm disasm <file.cvmb>           Disassemble bytecode
//   cvm debug <file.cvmb>            Step debugger with execution trace

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(
    name = "cvm",
    version = "0.1.0",
    about = "Cryptographic Virtual Machine — a stack-based VM with first-class crypto opcodes",
    long_about = "CVM is a stack-based virtual machine whose instruction set treats cryptographic\n\
                  operations (hashing, symmetric encryption, asymmetric signatures, key derivation)\n\
                  as first-class opcodes. Keys are opaque handles — raw material never touches the stack."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a CVM bytecode file
    Run {
        /// Path to .cvmb bytecode file
        file: PathBuf,
        /// Gas limit (0 = unlimited)
        #[arg(long, default_value_t = 0)]
        gas_limit: u64,
        /// Enable execution trace output
        #[arg(long)]
        trace: bool,
    },

    /// Assemble a .cvmasm source file into .cvmb bytecode
    Asm {
        /// Path to .cvmasm source file
        file: PathBuf,
        /// Output path for .cvmb bytecode
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Disassemble a .cvmb bytecode file to human-readable assembly
    Disasm {
        /// Path to .cvmb bytecode file
        file: PathBuf,
    },

    /// Run with step-by-step execution trace (debug mode)
    Debug {
        /// Path to .cvmb bytecode file
        file: PathBuf,
        /// Gas limit (0 = unlimited)
        #[arg(long, default_value_t = 0)]
        gas_limit: u64,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Run { file, gas_limit, trace } => cmd_run(&file, gas_limit, trace),
        Commands::Asm { file, output } => cmd_asm(&file, output),
        Commands::Disasm { file } => cmd_disasm(&file),
        Commands::Debug { file, gas_limit } => cmd_debug(&file, gas_limit),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn cmd_run(file: &PathBuf, gas_limit: u64, trace: bool) -> Result<(), Box<dyn std::error::Error>> {
    let bytecode = fs::read(file)?;
    let crypto = cvm_crypto::CvmCryptoDispatcher::new();

    if gas_limit > 0 {
        let sandbox = cvm_sandbox::ExecutionPolicy::with_gas_limit(gas_limit);
        let mut vm = cvm_core::Vm::with_providers(&bytecode, crypto, sandbox)?;
        if trace { vm.enable_trace(); }
        vm.execute()?;
        if trace { print_trace(&vm.trace); }
        eprintln!("[CVM] Execution completed. Steps: {}", vm.steps);
    } else {
        let sandbox = cvm_sandbox::ExecutionPolicy::unrestricted();
        let mut vm = cvm_core::Vm::with_providers(&bytecode, crypto, sandbox)?;
        if trace { vm.enable_trace(); }
        vm.execute()?;
        if trace { print_trace(&vm.trace); }
        eprintln!("[CVM] Execution completed. Steps: {}", vm.steps);
    }

    Ok(())
}

fn cmd_asm(file: &PathBuf, output: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let source = fs::read_to_string(file)?;
    let bytecode = cvm_asm::assemble(&source)
        .map_err(|e| format!("Assembly failed: {}", e))?;

    let out_path = output.unwrap_or_else(|| {
        file.with_extension("cvmb")
    });

    fs::write(&out_path, &bytecode)?;
    eprintln!("[CVM] Assembled {} -> {} ({} bytes)",
        file.display(), out_path.display(), bytecode.len());
    Ok(())
}

fn cmd_disasm(file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let bytecode = fs::read(file)?;
    let output = cvm_disasm::disassemble(&bytecode)?;
    print!("{}", output);
    Ok(())
}

fn cmd_debug(file: &PathBuf, gas_limit: u64) -> Result<(), Box<dyn std::error::Error>> {
    let bytecode = fs::read(file)?;
    let crypto = cvm_crypto::CvmCryptoDispatcher::new();
    let sandbox = if gas_limit > 0 {
        cvm_sandbox::ExecutionPolicy::with_gas_limit(gas_limit)
    } else {
        cvm_sandbox::ExecutionPolicy::unrestricted()
    };

    let mut vm = cvm_core::Vm::with_providers(&bytecode, crypto, sandbox)?;
    vm.enable_trace();

    match vm.execute() {
        Ok(()) => eprintln!("[CVM] Program completed normally."),
        Err(e) => eprintln!("[CVM] Program terminated with: {}", e),
    }

    eprintln!("[CVM] Total steps: {}", vm.steps);
    eprintln!("\n=== Execution Trace ===");
    print_trace(&vm.trace);

    Ok(())
}

fn print_trace(trace: &[cvm_core::TraceRecord]) {
    for record in trace {
        eprintln!("  0x{:04X}: {:12}  stack=[{}]",
            record.pc,
            record.opcode.mnemonic(),
            record.stack_snapshot.join(", "));
    }
}
