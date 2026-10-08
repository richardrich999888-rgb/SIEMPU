//! CLI entry point; all logic lives in the library so it can be tested without a process.

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (status, stdout, stderr) = siepmu_evidence_verify::cli::run(&args);
    // Output failures (closed pipe) cannot change the verdict; the exit status still carries it.
    let _ = std::io::stdout().write_all(stdout.as_bytes());
    let _ = std::io::stderr().write_all(stderr.as_bytes());
    if status == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
