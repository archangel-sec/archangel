//! Structured model-output parsing — threat model layer **#5**.
//!
//! The model's expressible output is **bounded**: it may emit exactly one
//! JSON object selecting a tool (with string args), or asking the operator
//! a question, or refusing. It can never emit free-form prose that is acted
//! on, and never raw shell. This is what turns "the LLM said something" into
//! "the LLM selected one pre-approved, policy-checked action".
//!
//! Parsing is strict and fail-closed on purpose. A response that does not
//! match the contract is **not** coerced into an action — it is reported as
//! a contract violation and nothing runs. Being lenient here would reopen
//! the very gap layers #1–#4 work to close, because this text is
//! attacker-influenceable via prompt injection.
//!
//! Order: the canary check (#3) runs *first* — if the model leaked the
//! session canary it has been subverted, and we return [`ResponseError::
//! CanaryLeaked`] so the caller aborts and audits the session instead of
//! parsing hostile output.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::prompt::PromptBuilder;

/// A structured action chosen by the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelAction {
    /// Invoke a named `.exec` tool with string arguments.
    Invoke {
        /// Tool (bundle) name. Validated as a safe token; policy decides
        /// whether it is actually permitted.
        exec: String,
        /// Argument values (validated later against the bundle schema).
        args: BTreeMap<String, String>,
        /// The model's stated rationale (for the audit log / operator).
        reason: String,
    },
    /// Ask the operator a clarifying question; take no action.
    Ask {
        /// The question.
        question: String,
    },
    /// Decline to act.
    Refuse {
        /// Why.
        reason: String,
    },
}

/// Why a response could not be turned into a bounded action.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResponseError {
    /// The session canary leaked into the output (#3): the model has been
    /// subverted. The caller MUST abort and audit the session.
    #[error("canary leaked: model subverted, abort session")]
    CanaryLeaked,

    /// Response was empty.
    #[error("empty model response")]
    Empty,

    /// Response exceeded the sanity size cap (a bounded action is tiny).
    #[error("model response too large ({0} bytes)")]
    TooLarge(usize),

    /// Response was not exactly one JSON object (prose, trailing data,
    /// multiple objects, …). Bounded-output contract violated.
    #[error("response is not a single JSON action object: {0}")]
    NotContractJson(String),

    /// JSON parsed but did not match the action schema.
    #[error("response did not match the action schema: {0}")]
    BadShape(String),

    /// The chosen tool name is not a safe single token.
    #[error("unsafe tool name {0:?}")]
    UnsafeExecName(String),
}

/// Generous cap: a structured action (with a reason) is tiny; anything
/// approaching this is already not a well-formed action.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Same rule the executor enforces on bundle names (path-traversal /
/// injection defense). Kept here too so a bad name is rejected early.
fn safe_exec_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Strip a single Markdown code fence if the model wrapped its JSON in one.
/// Real models do this often; we tolerate exactly one wrapper and nothing
/// else (no prose before/after — `serde_json` then enforces single-object).
fn strip_one_fence(s: &str) -> &str {
    let t = s.trim();
    let Some(rest) = t.strip_prefix("```") else {
        return t;
    };
    // Drop the rest of the fence-open line (e.g. ```json).
    let after_lang = rest.find('\n').map_or("", |i| rest.get(i + 1..).unwrap_or(""));
    after_lang.trim().strip_suffix("```").unwrap_or(after_lang).trim()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAction {
    action: String,
    #[serde(default)]
    args: Option<BTreeMap<String, String>>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    question: Option<String>,
}

/// Parse one model response into a bounded [`ModelAction`].
///
/// `builder` supplies the per-session canary for the #3 pre-check.
pub fn parse_model_response(
    raw: &str,
    builder: &PromptBuilder,
) -> Result<ModelAction, ResponseError> {
    // #3 first — never parse output from a model we can prove is subverted.
    if builder.response_is_compromised(raw) {
        return Err(ResponseError::CanaryLeaked);
    }
    if raw.trim().is_empty() {
        return Err(ResponseError::Empty);
    }
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(ResponseError::TooLarge(raw.len()));
    }

    let json = strip_one_fence(raw);
    if !(json.starts_with('{') && json.ends_with('}')) {
        return Err(ResponseError::NotContractJson(
            "expected a single JSON object".to_owned(),
        ));
    }
    // `from_str` rejects trailing data, so this enforces exactly one object.
    let parsed: RawAction = serde_json::from_str(json)
        .map_err(|e| ResponseError::NotContractJson(e.to_string()))?;

    match parsed.action.as_str() {
        "ask" => {
            let question = parsed.question.ok_or_else(|| {
                ResponseError::BadShape("'ask' requires 'question'".to_owned())
            })?;
            Ok(ModelAction::Ask { question })
        }
        "refuse" => {
            let reason = parsed.reason.ok_or_else(|| {
                ResponseError::BadShape("'refuse' requires 'reason'".to_owned())
            })?;
            Ok(ModelAction::Refuse { reason })
        }
        tool => {
            if !safe_exec_name(tool) {
                return Err(ResponseError::UnsafeExecName(tool.to_owned()));
            }
            Ok(ModelAction::Invoke {
                exec: tool.to_owned(),
                args: parsed.args.unwrap_or_default(),
                reason: parsed.reason.unwrap_or_default(),
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use archangel_core::OperationMode;

    use crate::prompt::{PromptBuilder, SessionSecrets};

    use super::{parse_model_response, ModelAction, ResponseError};

    fn builder() -> PromptBuilder {
        PromptBuilder::new(SessionSecrets::generate(), OperationMode::ReadOnly)
    }

    #[test]
    fn parses_invoke() {
        let b = builder();
        let r = parse_model_response(
            r#"{"action":"read-logs","args":{"service":"nginx"},"reason":"check"}"#,
            &b,
        )
        .expect("valid");
        let mut want_args = std::collections::BTreeMap::new();
        want_args.insert("service".to_owned(), "nginx".to_owned());
        assert_eq!(
            r,
            ModelAction::Invoke {
                exec: "read-logs".to_owned(),
                args: want_args,
                reason: "check".to_owned(),
            }
        );
    }

    #[test]
    fn parses_ask_and_refuse() {
        let b = builder();
        assert!(matches!(
            parse_model_response(r#"{"action":"ask","question":"which host?"}"#, &b),
            Ok(ModelAction::Ask { .. })
        ));
        assert!(matches!(
            parse_model_response(r#"{"action":"refuse","reason":"unsafe"}"#, &b),
            Ok(ModelAction::Refuse { .. })
        ));
    }

    #[test]
    fn strips_one_code_fence() {
        let b = builder();
        let r = parse_model_response(
            "```json\n{\"action\":\"refuse\",\"reason\":\"no\"}\n```",
            &b,
        );
        assert!(matches!(r, Ok(ModelAction::Refuse { .. })));
    }

    #[test]
    fn canary_leak_aborts_before_parse() {
        let b = builder();
        // Even though this is otherwise valid JSON, a leaked canary wins.
        let raw = format!(
            r#"{{"action":"refuse","reason":"{}"}}"#,
            b.secrets().canary()
        );
        assert!(matches!(
            parse_model_response(&raw, &b),
            Err(ResponseError::CanaryLeaked)
        ));
    }

    #[test]
    fn prose_around_json_is_rejected() {
        let b = builder();
        assert!(matches!(
            parse_model_response(
                r#"Sure! Here you go: {"action":"refuse","reason":"x"}"#,
                &b
            ),
            Err(ResponseError::NotContractJson(_))
        ));
    }

    #[test]
    fn trailing_second_object_is_rejected() {
        let b = builder();
        assert!(matches!(
            parse_model_response(
                r#"{"action":"refuse","reason":"x"}{"action":"ask","question":"y"}"#,
                &b
            ),
            Err(ResponseError::NotContractJson(_))
        ));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let b = builder();
        assert!(matches!(
            parse_model_response(
                r#"{"action":"refuse","reason":"x","backdoor":true}"#,
                &b
            ),
            Err(ResponseError::NotContractJson(_))
        ));
    }

    #[test]
    fn unsafe_tool_name_is_rejected() {
        let b = builder();
        assert!(matches!(
            parse_model_response(
                r#"{"action":"../../bin/sh","args":{},"reason":"x"}"#,
                &b
            ),
            Err(ResponseError::UnsafeExecName(_))
        ));
    }

    #[test]
    fn empty_is_rejected() {
        let b = builder();
        assert!(matches!(
            parse_model_response("   ", &b),
            Err(ResponseError::Empty)
        ));
    }

    #[test]
    fn oversized_is_rejected() {
        let b = builder();
        let huge = format!(
            r#"{{"action":"refuse","reason":"{}"}}"#,
            "A".repeat(70 * 1024)
        );
        assert!(matches!(
            parse_model_response(&huge, &b),
            Err(ResponseError::TooLarge(_))
        ));
    }
}
