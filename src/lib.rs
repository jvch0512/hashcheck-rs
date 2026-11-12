//! File integrity tooling: manifests, verification and duplicate detection.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Hash a file with SHA-256 using a streaming buffer, returning lowercase hex.
pub fn hash_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Recursively list regular files (symlinks are skipped on purpose), sorted for deterministic output.
pub fn walk(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file() {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    Ok(out)
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Build a manifest in the `sha256sum` format: `<hash>  <relative path>`.
pub fn build_manifest(root: &Path) -> io::Result<String> {
    let mut s = String::new();
    for p in walk(root)? {
        s.push_str(&format!("{}  {}\n", hash_file(&p)?, rel(root, &p)));
    }
    Ok(s)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub ok: usize,
    pub modified: Vec<String>,
    pub missing: Vec<String>,
    pub added: Vec<String>,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.modified.is_empty() && self.missing.is_empty() && self.added.is_empty()
    }
}

/// Parse a manifest. Rejects absolute paths and `..` so a hostile manifest cannot point outside the root.
pub fn parse_manifest(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut m = BTreeMap::new();
    for (i, line) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let (h, p) = line
            .split_once("  ")
            .ok_or(format!("line {}: expected '<hash>  <path>'", i + 1))?;
        if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("line {}: invalid SHA-256", i + 1));
        }
        if p.starts_with('/') || p.contains("..") || p.contains(':') {
            return Err(format!("line {}: unsafe path '{}'", i + 1, p));
        }
        m.insert(p.to_string(), h.to_lowercase());
    }
    Ok(m)
}

/// Compare a directory against a manifest.
pub fn verify(root: &Path, manifest: &str) -> Result<Report, String> {
    let expected = parse_manifest(manifest)?;
    let mut r = Report {
        ok: 0,
        modified: vec![],
        missing: vec![],
        added: vec![],
    };
    for (p, h) in &expected {
        match hash_file(&root.join(p)) {
            Ok(actual) if &actual == h => r.ok += 1,
            Ok(_) => r.modified.push(p.clone()),
            Err(_) => r.missing.push(p.clone()),
        }
    }
    for p in walk(root).map_err(|e| e.to_string())? {
        let name = rel(root, &p);
        if !expected.contains_key(&name) {
            r.added.push(name);
        }
    }
    Ok(r)
}

/// Group files with identical content. Returns only groups with 2+ files; cheap size pre-filter first.
pub fn find_duplicates(root: &Path) -> io::Result<Vec<Vec<String>>> {
    let mut by_size: BTreeMap<u64, Vec<PathBuf>> = BTreeMap::new();
    for p in walk(root)? {
        by_size
            .entry(std::fs::metadata(&p)?.len())
            .or_default()
            .push(p);
    }
    let mut groups = Vec::new();
    for (_, files) in by_size.into_iter().filter(|(_, v)| v.len() > 1) {
        let mut by_hash: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for f in files {
            by_hash
                .entry(hash_file(&f)?)
                .or_default()
                .push(rel(root, &f));
        }
        groups.extend(by_hash.into_values().filter(|v| v.len() > 1));
    }
    groups.sort();
    Ok(groups)
}
