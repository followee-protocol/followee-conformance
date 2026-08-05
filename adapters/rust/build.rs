//! Build-time identity for the hello handshake (HARNESS.md Section 8).
//!
//! The implementation and specification commits are read from the verified
//! submodule checkouts at build time and embedded into the binary.  They
//! are never accepted from a runtime environment variable.  The
//! orchestrator independently re-verifies both values against the
//! HARNESS.md Section 2 pins.

use std::path::{Path, PathBuf};
use std::process::Command;

fn git_maybe(dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run git in {}: {e}", dir.display()));
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8(output.stdout)
            .expect("git output was not UTF-8")
            .trim()
            .to_string(),
    )
}

fn git(dir: &Path, args: &[&str]) -> String {
    git_maybe(dir, args).unwrap_or_else(|| panic!("git {:?} failed in {}", args, dir.display()))
}

fn head_commit(dir: &Path) -> String {
    let commit = git(dir, &["rev-parse", "HEAD"]);
    let valid = commit.len() == 40
        && commit
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if !valid {
        panic!("unexpected commit id {commit:?} in {}", dir.display());
    }
    commit
}

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let impl_dir = manifest_dir.join("../../implementations/followee-rs");
    let spec_dir = manifest_dir.join("../../specification");

    let impl_commit = head_commit(&impl_dir);
    let spec_commit = head_commit(&spec_dir);
    println!("cargo:rustc-env=FOLLOWEE_IMPL_COMMIT={impl_commit}");
    println!("cargo:rustc-env=FOLLOWEE_SPEC_COMMIT={spec_commit}");

    // Rebuild whenever either checkout moves.  A detached HEAD stores the
    // commit directly in HEAD; a symbolic HEAD stores only the branch name,
    // so the branch's loose ref file and packed-refs must be watched too
    // (only existing paths are emitted: a missing rerun-if-changed path
    // would force a rebuild on every invocation).
    for dir in [&impl_dir, &spec_dir] {
        let git_dir = PathBuf::from(git(dir, &["rev-parse", "--absolute-git-dir"]));
        watch_if_exists(&git_dir.join("HEAD"));
        if let Some(branch_ref) = git_maybe(dir, &["symbolic-ref", "-q", "HEAD"]) {
            watch_if_exists(&git_dir.join(&branch_ref));
            watch_if_exists(&git_dir.join("packed-refs"));
        }
    }
}

fn watch_if_exists(path: &Path) {
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
