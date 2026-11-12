use hashcheck_rs::{build_manifest, find_duplicates, verify};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "hashcheck <command>\n  manifest <dir> [-o file]   write SHA-256 manifest (sha256sum format)\n  verify <dir> <manifest>    exit 1 if anything changed, is missing or was added\n  dupes <dir>                list files with identical content";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["manifest", dir] => {
            print_or_fail(build_manifest(Path::new(dir)).map_err(|e| e.to_string()))
        }
        ["manifest", dir, "-o", out] => {
            match build_manifest(Path::new(dir)).and_then(|m| std::fs::write(out, m)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e.to_string()),
            }
        }
        ["verify", dir, manifest] => {
            let text = match std::fs::read_to_string(manifest) {
                Ok(t) => t,
                Err(e) => return fail(&e.to_string()),
            };
            match verify(Path::new(dir), &text) {
                Ok(r) => {
                    println!(
                        "{} ok, {} modified, {} missing, {} added",
                        r.ok,
                        r.modified.len(),
                        r.missing.len(),
                        r.added.len()
                    );
                    for (tag, v) in [
                        ("MODIFIED", &r.modified),
                        ("MISSING", &r.missing),
                        ("ADDED", &r.added),
                    ] {
                        v.iter().for_each(|p| println!("  {tag}: {p}"));
                    }
                    if r.is_clean() {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(1)
                    }
                }
                Err(e) => fail(&e),
            }
        }
        ["dupes", dir] => match find_duplicates(Path::new(dir)) {
            Ok(groups) => {
                for g in &groups {
                    println!("duplicate group ({} files):", g.len());
                    g.iter().for_each(|p| println!("  {p}"));
                }
                println!("{} duplicate group(s)", groups.len());
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e.to_string()),
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn print_or_fail(r: Result<String, String>) -> ExitCode {
    match r {
        Ok(s) => {
            print!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("error: {msg}");
    ExitCode::from(2)
}
