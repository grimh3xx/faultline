//! A small dumb-mutation crash fuzzer.
//!
//! faultline feeds mutated inputs to a target you are authorized to test and
//! records the ones that crash it (killed by SIGSEGV/SIGABRT/SIGBUS/SIGILL/
//! SIGFPE). It is a triage aid for exploit development, not a coverage-guided
//! engine — point it at a known-suspect binary and let it surface crashing
//! inputs to minimise and analyse by hand.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rand::Rng;

/// How the mutated bytes reach the target.
#[derive(Debug, Clone)]
pub enum Delivery {
    /// Write to the child's stdin.
    Stdin,
    /// Replace the `@@` token in the args with a temp file path.
    File,
    /// Append the input as the final argument.
    Arg,
}

pub struct FuzzOpts {
    pub target: String,
    pub args: Vec<String>,
    pub delivery: Delivery,
    pub seed: Vec<u8>,
    pub iterations: usize,
    pub max_mutations: usize,
    pub timeout: Duration,
    pub out_dir: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Crash {
    pub iteration: usize,
    pub signal: i32,
    pub input_len: usize,
    pub saved_as: String,
}

/// "Interesting" bytes that often trip parsers and bounds checks.
const INTERESTING: &[u8] = &[0x00, 0x01, 0x7f, 0x80, 0xff, 0x41, 0x25, 0x0a, 0x2f];

/// Mutate a copy of `seed` with up to `max_mutations` random edits.
fn mutate(seed: &[u8], max_mutations: usize, rng: &mut impl Rng) -> Vec<u8> {
    let mut buf = if seed.is_empty() {
        vec![0x41u8; rng.gen_range(1..=64)]
    } else {
        seed.to_vec()
    };
    let n = rng.gen_range(1..=max_mutations.max(1));
    for _ in 0..n {
        match rng.gen_range(0..5) {
            0 if !buf.is_empty() => {
                // Bit flip.
                let i = rng.gen_range(0..buf.len());
                buf[i] ^= 1 << rng.gen_range(0..8);
            }
            1 if !buf.is_empty() => {
                // Set an interesting byte.
                let i = rng.gen_range(0..buf.len());
                buf[i] = INTERESTING[rng.gen_range(0..INTERESTING.len())];
            }
            2 => {
                // Grow with a run of a repeated byte (overflow probe).
                let b = INTERESTING[rng.gen_range(0..INTERESTING.len())];
                let extra = rng.gen_range(1..=256);
                buf.extend(std::iter::repeat(b).take(extra));
            }
            3 if buf.len() > 1 => {
                // Truncate.
                let keep = rng.gen_range(1..buf.len());
                buf.truncate(keep);
            }
            _ => {
                // Insert a random byte.
                let i = rng.gen_range(0..=buf.len());
                buf.insert(i, rng.gen());
            }
        }
    }
    buf
}

/// Spawn the target with the input delivered per `opts`, poll with the timeout,
/// and return the raw exit status (or `None` if we killed it for hanging).
/// Shared across platforms so delivery, timeout and temp-file handling are
/// identical; only the crash interpretation in `run_once` differs.
fn run_target(opts: &FuzzOpts, input: &[u8]) -> Result<Option<std::process::ExitStatus>> {
    let mut tmp: Option<TempFile> = None;
    let mut cmd = Command::new(&opts.target);
    match &opts.delivery {
        Delivery::Stdin => {
            cmd.args(&opts.args).stdin(Stdio::piped());
        }
        Delivery::Arg => {
            cmd.args(&opts.args)
                .arg(String::from_utf8_lossy(input).to_string());
        }
        Delivery::File => {
            let path = std::env::temp_dir().join(format!("faultline_{}", std::process::id()));
            std::fs::write(&path, input).ok();
            let args: Vec<String> = opts
                .args
                .iter()
                .map(|a| {
                    if a == "@@" {
                        path.to_string_lossy().to_string()
                    } else {
                        a.clone()
                    }
                })
                .collect();
            cmd.args(args);
            tmp = Some(TempFile(path));
        }
    }
    cmd.stdout(Stdio::null()).stderr(Stdio::null());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning {}", opts.target))?;
    if matches!(opts.delivery, Delivery::Stdin) {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input);
        }
    }

    // Poll with a timeout; kill if the target hangs.
    let deadline = Instant::now() + opts.timeout;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break Some(status),
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    };
    drop(tmp);
    Ok(status)
}

/// Run one input and return a crash indicator: the terminating signal on Unix,
/// or an abnormal (>= 0xC0000000) exit code on Windows.
#[cfg(unix)]
fn run_once(opts: &FuzzOpts, input: &[u8]) -> Result<Option<i32>> {
    use std::os::unix::process::ExitStatusExt;
    Ok(run_target(opts, input)?.and_then(|s| s.signal()))
}

#[cfg(not(unix))]
fn run_once(opts: &FuzzOpts, input: &[u8]) -> Result<Option<i32>> {
    Ok(run_target(opts, input)?.and_then(|s| {
        let code = s.code().unwrap_or(0);
        if (code as u32) >= 0xC000_0000 {
            Some(code)
        } else {
            None
        }
    }))
}

/// RAII temp-file cleanup helper (File delivery).
struct TempFile(PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Run the fuzzing loop. Returns the crashes found.
pub fn run(opts: &FuzzOpts, mut on_progress: impl FnMut(usize)) -> Result<Vec<Crash>> {
    std::fs::create_dir_all(&opts.out_dir)
        .with_context(|| format!("creating {}", opts.out_dir.display()))?;
    let mut rng = rand::thread_rng();
    let mut crashes = Vec::new();

    for i in 0..opts.iterations {
        let input = mutate(&opts.seed, opts.max_mutations, &mut rng);
        if let Some(sig) = run_once(opts, &input)? {
            if is_crash(sig) {
                let name = format!("crash_{:04}_sig{}.bin", i, sig);
                let path = opts.out_dir.join(&name);
                std::fs::write(&path, &input).ok();
                crashes.push(Crash {
                    iteration: i,
                    signal: sig,
                    input_len: input.len(),
                    saved_as: path.to_string_lossy().to_string(),
                });
            }
        }
        if i % 100 == 0 {
            on_progress(i);
        }
    }
    Ok(crashes)
}

/// Signals that indicate a genuine crash worth saving.
fn is_crash(sig: i32) -> bool {
    // SIGILL=4, SIGABRT=6, SIGBUS=7, SIGFPE=8, SIGSEGV=11. On Windows a crash
    // surfaces as a high (>= 0xC0000000) status code, compared unsigned.
    matches!(sig, 4 | 6 | 7 | 8 | 11) || (sig as u32) >= 0xC000_0000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_changes_or_grows_input() {
        let mut rng = rand::thread_rng();
        let seed = b"AAAAAAAA".to_vec();
        // Over several tries at least one mutation differs from the seed.
        let differs = (0..32).any(|_| mutate(&seed, 4, &mut rng) != seed);
        assert!(differs);
    }

    #[test]
    fn empty_seed_produces_input() {
        let mut rng = rand::thread_rng();
        assert!(!mutate(&[], 4, &mut rng).is_empty());
    }

    #[test]
    fn classifies_crash_signals() {
        assert!(is_crash(11)); // SIGSEGV
        assert!(is_crash(6)); // SIGABRT
        assert!(!is_crash(0));
        assert!(!is_crash(15)); // SIGTERM (our own timeout kill) is not a crash
    }
}
