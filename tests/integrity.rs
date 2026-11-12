use hashcheck_rs::*;
use std::fs;

const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[test]
fn known_vectors() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("e"), b"").unwrap();
    fs::write(d.path().join("a"), b"abc").unwrap();
    assert_eq!(hash_file(&d.path().join("e")).unwrap(), EMPTY);
    assert_eq!(hash_file(&d.path().join("a")).unwrap(), ABC);
}

#[test]
fn manifest_then_verify_detects_every_change() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("sub")).unwrap();
    fs::write(d.path().join("a.txt"), "one").unwrap();
    fs::write(d.path().join("sub/b.txt"), "two").unwrap();
    fs::write(d.path().join("gone.txt"), "x").unwrap();
    let m = build_manifest(d.path()).unwrap();
    assert!(verify(d.path(), &m).unwrap().is_clean());

    fs::write(d.path().join("a.txt"), "ONE").unwrap();
    fs::remove_file(d.path().join("gone.txt")).unwrap();
    fs::write(d.path().join("new.txt"), "n").unwrap();
    let r = verify(d.path(), &m).unwrap();
    assert_eq!(r.modified, vec!["a.txt"]);
    assert_eq!(r.missing, vec!["gone.txt"]);
    assert_eq!(r.added, vec!["new.txt"]);
    assert_eq!(r.ok, 1);
}

#[test]
fn hostile_manifests_are_rejected() {
    let h = ABC;
    for bad in [
        format!("{h}  /etc/passwd"),
        format!("{h}  ../secret"),
        format!("{h}  C:evil"),
        "nothex  file".into(),
        format!("{h} file"),
    ] {
        assert!(parse_manifest(&bad).is_err(), "should reject {bad}");
    }
    assert!(parse_manifest(&format!("{h}  ok/file.txt\n\n")).is_ok());
}

#[test]
fn duplicates_grouped_by_content_not_name() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("a"), "same").unwrap();
    fs::write(d.path().join("b"), "same").unwrap();
    fs::write(d.path().join("c"), "diff").unwrap(); // same size, different content
    fs::write(d.path().join("d"), "unique-length").unwrap();
    let g = find_duplicates(d.path()).unwrap();
    assert_eq!(g, vec![vec!["a".to_string(), "b".to_string()]]);
}

#[cfg(unix)]
#[test]
fn symlinks_are_not_followed() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("real"), "x").unwrap();
    std::os::unix::fs::symlink("/etc", d.path().join("link")).unwrap();
    assert_eq!(walk(d.path()).unwrap().len(), 1);
}
