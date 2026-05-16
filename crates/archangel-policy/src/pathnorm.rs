//! Lexical path normalization.
//!
//! # Why this is security-critical
//!
//! The compiled denylist matches **glob patterns** against filesystem paths.
//! If an action could touch `/etc/archangel/config` by writing the string
//! `/etc/archangel/../archangel/config`, `/etc//archangel/config`, or
//! `/etc/./archangel/config`, it would evade a naive glob match. This module
//! collapses those forms to a single canonical lexical representation
//! *before* matching, closing that evasion class.
//!
//! # What this deliberately does NOT do
//!
//! This is **lexical** normalization only. It does not resolve symlinks and
//! does not touch the filesystem. Symlink-based evasion (e.g. a symlink at
//! `/tmp/x` pointing into `/etc/ssh`) is **out of scope here by design**: it
//! is handled by the executor/sandbox, which operates on real file
//! descriptors with `O_NOFOLLOW`/`openat2(RESOLVE_*)` semantics and is the
//! actual enforcing TCB. The denylist is one layer of defense in depth; this
//! module hardens that layer against the *string* evasion class it can
//! reasonably defend against, and no more. Claiming otherwise would be a
//! dangerous overstatement of its guarantee.

use crate::error::PolicyError;

/// Normalize an absolute path lexically into canonical form.
///
/// Rules applied, in order:
/// - the path must be absolute (begin with `/`), else it is rejected
///   (fail-closed: a path we cannot anchor we will not declare safe);
/// - an embedded NUL byte rejects the path (defense against truncation
///   tricks in downstream C APIs);
/// - `//` runs and `.` components are removed;
/// - `..` pops the previous component, never escaping above `/`
///   (matching the kernel's treatment of `/..` as `/`);
/// - no trailing slash is kept, except for the root `/` itself.
pub fn normalize_absolute(path: &str) -> Result<String, PolicyError> {
    if path.as_bytes().first() != Some(&b'/') {
        return Err(PolicyError::BadPath(format!(
            "path is not absolute: {path:?}"
        )));
    }
    if path.contains('\0') {
        return Err(PolicyError::BadPath(
            "path contains an embedded NUL".to_owned(),
        ));
    }

    let mut stack: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            real => stack.push(real),
        }
    }

    if stack.is_empty() {
        return Ok("/".to_owned());
    }

    let mut out = String::with_capacity(path.len());
    for component in stack {
        out.push('/');
        out.push_str(component);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::normalize_absolute;

    #[test]
    fn collapses_double_slashes() {
        assert_eq!(
            normalize_absolute("/etc//archangel///config").unwrap_or_default(),
            "/etc/archangel/config"
        );
    }

    #[test]
    fn removes_dot_components() {
        assert_eq!(
            normalize_absolute("/etc/./archangel/./config").unwrap_or_default(),
            "/etc/archangel/config"
        );
    }

    #[test]
    fn resolves_dotdot() {
        assert_eq!(
            normalize_absolute("/etc/archangel/../archangel/config").unwrap_or_default(),
            "/etc/archangel/config"
        );
    }

    #[test]
    fn dotdot_cannot_escape_root() {
        assert_eq!(
            normalize_absolute("/../../../etc/shadow").unwrap_or_default(),
            "/etc/shadow"
        );
    }

    #[test]
    fn strips_trailing_slash() {
        assert_eq!(
            normalize_absolute("/etc/ssh/").unwrap_or_default(),
            "/etc/ssh"
        );
    }

    #[test]
    fn root_stays_root() {
        assert_eq!(normalize_absolute("/").unwrap_or_default(), "/");
        assert_eq!(normalize_absolute("/..").unwrap_or_default(), "/");
    }

    #[test]
    fn relative_path_is_rejected() {
        assert!(normalize_absolute("etc/passwd").is_err());
        assert!(normalize_absolute("../etc/passwd").is_err());
    }

    #[test]
    fn nul_byte_is_rejected() {
        assert!(normalize_absolute("/etc/ssh\0/../safe").is_err());
    }
}
