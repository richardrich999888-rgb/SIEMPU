//! Unix operator CLI. Never accepts keys or credentials on the command line.

#[cfg(not(unix))]
compile_error!("This laboratory operator CLI currently requires Unix file-permission semantics.");

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use siepmu_evidence_verify::json::{parse, Value};
use siepmu_nexora_bridge::{
    seal, strict_json, verify, Anchor, SigningMaterial, Snapshot, MAX_FILE_BYTES,
};

const USAGE: &str = "Usage: siepmu-nexora-bridge init PRIVATE_FILE PUBLIC_FILE SIGNER_ID KEY_VERSION\n       siepmu-nexora-bridge seal EVIDENCE AUTHORITY_KEY RETAINED_CHECKPOINT PRIVATE_FILE OUTPUT\n       siepmu-nexora-bridge verify SNAPSHOT AUTHORITY_KEY RETAINED_CHECKPOINT PUBLIC_FILE";

fn read(path: &str, secret: bool) -> Result<String, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "INPUT_OPEN_FAILED")?;
    let metadata = file.metadata().map_err(|_| "INPUT_METADATA_FAILED")?;
    let limit = if secret { 16 * 1024 } else { MAX_FILE_BYTES };
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("INPUT_NOT_REGULAR_OR_TOO_LARGE".to_owned());
    }
    if secret && metadata.permissions().mode() & 0o077 != 0 {
        return Err("PRIVATE_FILE_MUST_BE_OWNER_ONLY".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "INPUT_READ_FAILED")?;
    if bytes.len() > limit {
        return Err("INPUT_TOO_LARGE".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "INPUT_NOT_UTF8".to_owned())
}

fn read_native(path: &str) -> Result<Value, String> {
    parse(&read(path, false)?).map_err(|_| "INVALID_JSON".to_owned())
}

fn create(path: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err("OUTPUT_TOO_LARGE".to_owned());
    }
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "OUTPUT_EXISTS_OR_UNWRITABLE")?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "OUTPUT_WRITE_FAILED".to_owned())
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| "OUTPUT_ENCODING_FAILED")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn run(args: &[String]) -> Result<Option<serde_json::Value>, String> {
    match args.first().map(String::as_str) {
        Some("init") if args.len() == 5 => {
            let key_version = args[4]
                .parse::<u32>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or("INVALID_KEY_VERSION")?;
            if args[3].is_empty() || args[3].len() > 128 {
                return Err("INVALID_SIGNER_ID".to_owned());
            }
            let pair = aip_crypto::generate_ed25519_keypair();
            let anchor = Anchor {
                signer_id: args[3].clone(),
                key_version,
                public_key: pair
                    .public_key
                    .try_into()
                    .map_err(|_| "KEY_GENERATION_FAILED")?,
            };
            let material = SigningMaterial {
                anchor: anchor.clone(),
                private_key: pair
                    .private_key
                    .try_into()
                    .map_err(|_| "KEY_GENERATION_FAILED")?,
            };
            create(&args[1], &encode(&material)?)?;
            // If this second exclusive create fails, retain the owner-only private file;
            // never overwrite another anchor or print private material during recovery.
            create(&args[2], &encode(&anchor)?)?;
            Ok(None)
        }
        Some("seal") if args.len() == 6 => {
            let source = read(&args[1], false)?;
            let authority = read_native(&args[2])?;
            let checkpoint = read_native(&args[3])?;
            let material: SigningMaterial = strict_json(&read(&args[4], true)?)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "CLOCK_BEFORE_EPOCH")?
                .as_millis();
            let snapshot = seal(
                &source,
                &authority,
                &checkpoint,
                &material,
                u64::try_from(now).map_err(|_| "INVALID_TIME")?,
            )?;
            create(&args[5], &encode(&snapshot)?)?;
            Ok(None)
        }
        Some("verify") if args.len() == 5 => {
            let snapshot: Snapshot = strict_json(&read(&args[1], false)?)?;
            let authority = read_native(&args[2])?;
            let checkpoint = read_native(&args[3])?;
            let anchor: Anchor = strict_json(&read(&args[4], false)?)?;
            Ok(Some(verify(&snapshot, &authority, &checkpoint, &anchor)?))
        }
        _ => Err(USAGE.to_owned()),
    }
}

fn main() -> ExitCode {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(Some(result)) => match encode(&result) {
            Ok(bytes) => match std::io::stdout().write_all(&bytes) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            },
            Err(_) => ExitCode::FAILURE,
        },
        Ok(None) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
