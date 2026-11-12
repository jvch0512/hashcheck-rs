# hashcheck-rs

Small Rust CLI for **file integrity**: create SHA-256 manifests, verify a directory against one, and find duplicate files. The manifest uses the standard `sha256sum` format, so it stays compatible with `sha256sum -c`.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Usage

```bash
cargo install --path .
hashcheck manifest ./release -o SHA256SUMS
hashcheck verify ./release SHA256SUMS     # exit 1 on any modified, missing or added file
hashcheck dupes ~/Downloads
```

Typical uses: detect tampering of a deployed directory (a poor man's FIM), verify a release artifact set, clean up duplicate downloads.

## Security-minded design

* Streaming hashing with a 64 KiB buffer: constant memory on huge files
* Manifests are untrusted input: absolute paths, `..` and drive prefixes are rejected, so a crafted manifest cannot make the tool read files outside the target directory
* Symlinks are never followed (no escape through links, no loops)
* Duplicate search filters by size first and hashes only candidates
* Deterministic, sorted output; clear exit codes (0 clean, 1 differences, 2 usage or I/O error)

## Development

```bash
cargo clippy --all-targets -- -D warnings && cargo test
```

MIT licensed.
