//! Argument schema validation — threat model layer #7.
//!
//! The LLM proposes argument *values*; the bundle author declares the
//! *schema*. This module is where untrusted values meet a trusted schema.
//! It is strict and fail-closed:
//!
//! - every `required` argument must be present;
//! - every supplied argument must be declared — an **undeclared argument is
//!   rejected**, never passed through (that is the argument-injection
//!   vector: smuggling `--extra-flag` into a command the operator vetted);
//! - each value must fully match its declared regex. The pattern is anchored
//!   as `\A(?:…)\z`, so an operator who forgets `^`/`$` does not accidentally
//!   accept `safe-value; rm -rf /`;
//! - regexes are compiled with the linear-time `regex` engine, so a value
//!   cannot cause catastrophic backtracking (ReDoS) regardless of length.

use std::collections::BTreeMap;

use regex::Regex;

use crate::{
    error::ExecFormatError,
    manifest::{ArgType, ExecManifest},
};

/// Validate `provided` argument values against `manifest`'s `[args]` schema.
pub(crate) fn validate(
    manifest: &ExecManifest,
    provided: &BTreeMap<String, String>,
) -> Result<(), ExecFormatError> {
    // Reject anything not declared (argument injection defense).
    for name in provided.keys() {
        if !manifest.args.contains_key(name) {
            return Err(ExecFormatError::ArgRejected(format!(
                "undeclared argument {name:?}"
            )));
        }
    }

    for (name, spec) in &manifest.args {
        match provided.get(name) {
            None => {
                if spec.required {
                    return Err(ExecFormatError::ArgRejected(format!(
                        "missing required argument {name:?}"
                    )));
                }
            }
            Some(value) => {
                // v0.1: the only type is `string`; every supplied value is
                // a string, so the type check is total. Kept explicit so a
                // future numeric/bool type cannot silently skip validation.
                match spec.ty {
                    ArgType::String => {}
                }

                if let Some(pattern) = &spec.regex {
                    let anchored = format!(r"\A(?:{pattern})\z");
                    let re =
                        Regex::new(&anchored).map_err(|source| ExecFormatError::BadArgRegex {
                            arg: name.clone(),
                            source,
                        })?;
                    if !re.is_match(value) {
                        return Err(ExecFormatError::ArgRejected(format!(
                            "argument {name:?} value does not match its schema pattern"
                        )));
                    }
                }
            }
        }
    }

    Ok(())
}
