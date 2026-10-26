// SPDX-License-Identifier: Apache-2.0
use std::io::{self, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!("lgi-agent [--help|--version]\nRead-only local Linux inventory in JSON. Does not require sudo.\nDoes not perform attestation or verify cryptographic integrity.");
        return;
    }
    if args == ["--version"] {
        println!("lgi-agent {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if !args.is_empty() {
        eprintln!("Unsupported arguments. See lgi-agent --help.");
        std::process::exit(2);
    }
    if !cfg!(target_os = "linux") {
        eprintln!("This inventory requires Linux.");
        std::process::exit(2);
    }
    let report = lgi_agent::collect(&lgi_agent::LinuxSource);
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer_pretty(&mut stdout, &report).is_err() || writeln!(stdout).is_err() {
        eprintln!("Could not write the JSON report.");
        std::process::exit(1);
    }
}
