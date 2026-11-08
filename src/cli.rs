//! Command-line interface.

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "faultline",
    version,
    about = "An exploit-development toolkit: ROP gadgets, cyclic patterns, checksec, bad-chars and a crash fuzzer",
    long_about = "faultline collects the primitives you reach for when developing a memory-corruption \
exploit or working a CTF pwn challenge: ROP gadget discovery, De Bruijn offset patterns, a binary \
mitigation summary, bad-character buffers, and a dumb-mutation crash fuzzer. For use on binaries \
you own or are authorized to test."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Disable colored output.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Emit machine-readable JSON where applicable.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Find ROP (and optionally JOP) gadgets in an ELF/PE.
    Gadgets(GadgetsArgs),
    /// Generate a De Bruijn pattern, or find an offset within one.
    Cyclic(CyclicArgs),
    /// Summarize a binary's mitigations (NX, PIE, RELRO, canary, …).
    Checksec(FileArg),
    /// Emit a bad-character test buffer.
    Badchars(BadcharsArgs),
    /// Fuzz a target binary and record crashing inputs.
    Fuzz(FuzzArgs),
}

#[derive(Parser, Debug)]
pub struct FileArg {
    /// Path to the binary.
    pub file: String,
}

#[derive(Parser, Debug)]
pub struct GadgetsArgs {
    /// Path to the binary.
    pub file: String,

    /// Maximum instructions per gadget.
    #[arg(short, long, default_value_t = 6)]
    pub depth: usize,

    /// Also end gadgets on indirect jmp/call (JOP/COP).
    #[arg(long)]
    pub jop: bool,

    /// Keep only gadgets whose text contains this substring (e.g. "pop rdi").
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Maximum gadgets to return.
    #[arg(short, long, default_value_t = 2000)]
    pub limit: usize,
}

#[derive(Parser, Debug)]
pub struct CyclicArgs {
    /// Length of pattern to generate.
    pub length: Option<usize>,

    /// Instead, find the offset of this value (e.g. 0x6161616c or "laaa").
    #[arg(short, long)]
    pub offset: Option<String>,

    /// Subsequence length: 4 for 32-bit saved addresses, 8 for 64-bit.
    #[arg(short, long, default_value_t = 4)]
    pub n: usize,
}

#[derive(Parser, Debug)]
pub struct BadcharsArgs {
    /// Bytes to exclude, hex (e.g. "00,0a,0d").
    #[arg(short, long, default_value = "00")]
    pub exclude: String,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = BadFormat::Escapes)]
    pub format: BadFormat,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum BadFormat {
    /// `\xNN` escapes.
    Escapes,
    /// C array declaration.
    C,
    /// Raw bytes to stdout.
    Raw,
}

#[derive(Parser, Debug)]
pub struct FuzzArgs {
    /// Target binary to fuzz.
    #[arg(short, long)]
    pub target: String,

    /// Deliver the mutated input to the target's stdin (default).
    #[arg(long, group = "delivery")]
    pub stdin: bool,

    /// Deliver via a temp file whose path replaces `@@` in the args.
    #[arg(long, group = "delivery")]
    pub file: bool,

    /// Deliver as the final command-line argument.
    #[arg(long, group = "delivery")]
    pub arg: bool,

    /// Seed input file (otherwise a generated seed is used).
    #[arg(short, long)]
    pub seed: Option<String>,

    /// Number of inputs to try.
    #[arg(short, long, default_value_t = 5000)]
    pub iterations: usize,

    /// Maximum random edits per input.
    #[arg(long, default_value_t = 8)]
    pub max_mutations: usize,

    /// Per-run timeout in milliseconds.
    #[arg(long, default_value_t = 2000)]
    pub timeout: u64,

    /// Directory to write crashing inputs into.
    #[arg(short, long, default_value = "faultline-crashes")]
    pub out: String,

    /// Arguments passed to the target (use `@@` with --file).
    #[arg(last = true)]
    pub args: Vec<String>,
}
