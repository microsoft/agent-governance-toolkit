//! Validation helper: read base64-framed UTF-8 texts (one per line) from stdin,
//! normalize each, emit base64 of the normalized text. base64 framing keeps
//! arbitrary corpus text (newlines, unicode) safe across the pipe.
use std::io::{self, BufRead, Write};

use agentmesh::normalize::normalize;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let raw = STANDARD.decode(line.trim()).expect("valid base64");
        let text = String::from_utf8_lossy(&raw);
        let norm = normalize(&text);
        writeln!(out, "{}", STANDARD.encode(norm.text.as_bytes())).unwrap();
    }
}
