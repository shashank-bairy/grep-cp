//! Path sandbox. Every path the server opens is built from the configured root, a validated service
//! name and a filename returned by a directory listing — never from caller input directly. These
//! helpers enforce the remaining invariants (no separators, no traversal, symlinks stay in root).

use std::path::{Path, PathBuf};

/// A single path component that is safe to join onto a trusted directory.
pub fn is_safe_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

/// Canonicalizes `path` and returns it only if it stays inside `root_canon` (already canonical).
/// Symlinks are allowed only when their target is inside the root.
pub fn confine(root_canon: &Path, path: &Path) -> Option<PathBuf> {
    let canon = std::fs::canonicalize(path).ok()?;
    if canon.starts_with(root_canon) {
        Some(canon)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components() {
        for bad in ["", ".", "..", "a/b", "../x", "a\\b", "a\0b"] {
            assert!(!is_safe_component(bad), "{bad:?}");
        }
        for ok in ["orders", "host-1.log", "a..b", ".hidden"] {
            assert!(is_safe_component(ok), "{ok:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_outside_root_rejected() {
        let outside = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let root_canon = std::fs::canonicalize(root.path()).unwrap();
        std::fs::write(outside.path().join("secret"), b"x").unwrap();
        std::fs::write(root.path().join("inside"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), root.path().join("evil"))
            .unwrap();
        std::os::unix::fs::symlink(root.path().join("inside"), root.path().join("good")).unwrap();
        assert!(confine(&root_canon, &root.path().join("evil")).is_none());
        assert!(confine(&root_canon, &root.path().join("good")).is_some());
        assert!(confine(&root_canon, &root.path().join("missing")).is_none());
    }
}
