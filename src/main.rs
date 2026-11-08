//! faultline — an exploit-development toolkit.
//!
//! ROP gadget discovery, De Bruijn offset patterns, a binary mitigation summary
//! ("checksec"), bad-character buffers, and a dumb-mutation crash fuzzer — the
//! primitives you reach for when developing a memory-corruption exploit or
//! working a CTF pwn challenge. For binaries you own or are authorized to test.

mod badchars;
mod binary;
mod checksec;
mod cli;
mod cyclic;
mod fuzz;
mod gadgets;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use owo_colors::OwoColorize;

use cli::{BadFormat, Cli, Command};

fn main() -> ExitCode {
    let args = Cli::parse();
    if args.no_color || std::env::var_os("NO_COLOR").is_some() {
        owo_colors::set_override(false);
    }

    let result = match args.command {
        Command::Gadgets(a) => cmd_gadgets(a, args.json),
        Command::Cyclic(a) => cmd_cyclic(a, args.json),
        Command::Checksec(a) => cmd_checksec(a.file, args.json),
        Command::Badchars(a) => cmd_badchars(a),
        Command::Fuzz(a) => cmd_fuzz(a, args.json),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("  {} {e:#}", "error:".red().bold());
            ExitCode::from(2)
        }
    }
}

fn cmd_gadgets(a: cli::GadgetsArgs, json: bool) -> anyhow::Result<ExitCode> {
    let bytes = std::fs::read(&a.file)?;
    let image = binary::exec_image(&bytes)?;
    let opts = gadgets::Options {
        max_depth: a.depth,
        jop: a.jop,
        filter: a.filter,
        limit: a.limit,
    };
    let found = gadgets::find(&image, &opts);

    if json {
        println!("{}", serde_json::to_string_pretty(&found)?);
    } else {
        println!(
            "  {} {} gadget(s)  ·  {}-bit  ·  {}",
            "▸".bright_cyan(),
            found.len().to_string().bold(),
            image.bits,
            a.file.dimmed(),
        );
        let width = if image.bits == 64 { 16 } else { 8 };
        for g in &found {
            println!(
                "    {}  {}",
                format!("0x{:0width$x}", g.addr, width = width).bright_blue(),
                g.text,
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_cyclic(a: cli::CyclicArgs, json: bool) -> anyhow::Result<ExitCode> {
    if let Some(value) = a.offset {
        let needle = parse_offset(&value, a.n);
        match cyclic::find(&needle, a.n) {
            Some(off) => {
                if json {
                    println!("{{\"offset\": {off}}}");
                } else {
                    println!("  {} offset {}", "✓".bright_green(), off.to_string().bold());
                }
                Ok(ExitCode::SUCCESS)
            }
            None => {
                eprintln!("  {} value not found in the pattern", "·".dimmed());
                Ok(ExitCode::from(1))
            }
        }
    } else {
        let length = a.length.unwrap_or(256);
        let pat = cyclic::pattern(length, a.n);
        std::io::stdout().write_all(&pat).ok();
        println!();
        Ok(ExitCode::SUCCESS)
    }
}

/// Interpret an offset argument: `0x..`/decimal as a little-endian value, or a
/// short string as raw bytes.
fn parse_offset(s: &str, n: usize) -> Vec<u8> {
    let t = s.trim();
    let parsed = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    };
    match parsed {
        Some(v) => cyclic::value_to_needle(v, n),
        None => t.as_bytes().to_vec(),
    }
}

fn cmd_checksec(file: String, json: bool) -> anyhow::Result<ExitCode> {
    let bytes = std::fs::read(&file)?;
    let cs = checksec::analyze(&bytes)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&cs)?);
        return Ok(ExitCode::SUCCESS);
    }
    println!("  {} {}", "▸".bright_cyan(), file.bold());
    println!(
        "    {:<8} {} {}",
        "arch",
        cs.arch.bright_white(),
        format!("({}-bit)", cs.bits).dimmed()
    );
    row("NX", cs.nx, "NX enabled", "executable stack");
    row("PIE", cs.pie, "PIE / ASLR", "no PIE (fixed base)");
    relro_row(cs.relro);
    row("Canary", cs.canary, "stack canary", "no canary");
    row("FORTIFY", cs.fortify, "FORTIFY", "no FORTIFY");
    row(
        "RWX",
        !cs.rwx_segment,
        "no RWX segment",
        "RWX segment present!",
    );
    println!(
        "    {:<8} {}",
        "symbols",
        if cs.stripped {
            "stripped".yellow().to_string()
        } else {
            "present".green().to_string()
        }
    );
    Ok(ExitCode::SUCCESS)
}

/// Print a mitigation row. `secure` chooses the mark and which label shows.
fn row(name: &str, secure: bool, secure_text: &str, insecure_text: &str) {
    let (mark, label) = if secure {
        ("✓".green().to_string(), secure_text.green().to_string())
    } else {
        ("✗".red().to_string(), insecure_text.red().to_string())
    };
    println!("    {:<8} {} {}", name, mark, label);
}

fn relro_row(r: checksec::Relro) {
    let (mark, text) = match r {
        checksec::Relro::Full => ("✓".green().to_string(), "Full RELRO".green().to_string()),
        checksec::Relro::Partial => (
            "~".yellow().to_string(),
            "Partial RELRO".yellow().to_string(),
        ),
        checksec::Relro::None => ("✗".red().to_string(), "No RELRO".red().to_string()),
    };
    println!("    {:<8} {} {}", "RELRO", mark, text);
}

fn cmd_badchars(a: cli::BadcharsArgs) -> anyhow::Result<ExitCode> {
    let exclude = badchars::parse_bytes(&a.exclude).map_err(|e| anyhow::anyhow!(e))?;
    let buf = badchars::buffer(&exclude);
    match a.format {
        BadFormat::Escapes => println!("{}", badchars::as_escapes(&buf)),
        BadFormat::C => println!("{}", badchars::as_c_array(&buf)),
        BadFormat::Raw => {
            std::io::stdout().write_all(&buf).ok();
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_fuzz(a: cli::FuzzArgs, json: bool) -> anyhow::Result<ExitCode> {
    let delivery = if a.file {
        fuzz::Delivery::File
    } else if a.arg {
        fuzz::Delivery::Arg
    } else {
        fuzz::Delivery::Stdin
    };
    let seed = match &a.seed {
        Some(p) => std::fs::read(p)?,
        None => Vec::new(),
    };
    let opts = fuzz::FuzzOpts {
        target: a.target.clone(),
        args: a.args.clone(),
        delivery,
        seed,
        iterations: a.iterations,
        max_mutations: a.max_mutations,
        timeout: Duration::from_millis(a.timeout),
        out_dir: PathBuf::from(&a.out),
    };

    if !json {
        println!(
            "  {} fuzzing {}  ·  {} iterations  →  {}",
            "▸".bright_cyan(),
            a.target.bold(),
            a.iterations,
            a.out.dimmed(),
        );
    }
    let crashes = fuzz::run(&opts, |i| {
        if !json && i > 0 {
            print!("\r    {} {i} inputs…", "·".dimmed());
            std::io::stdout().flush().ok();
        }
    })?;

    if json {
        println!("{}", serde_json::to_string_pretty(&crashes)?);
    } else {
        println!();
        if crashes.is_empty() {
            println!(
                "  {} no crashes in {} iterations.",
                "·".dimmed(),
                a.iterations
            );
        } else {
            println!("  {} {} crash(es):", "✓".bright_green(), crashes.len());
            for c in &crashes {
                println!(
                    "    sig {} after {} bytes → {}",
                    c.signal.to_string().bright_red(),
                    c.input_len,
                    c.saved_as.dimmed(),
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
