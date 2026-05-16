//! Immutable denylist.
//!
//! Rules in this module are compiled into every archangel binary and cannot be
//! changed at runtime. Any change requires a code change, code review, and a
//! release. This is by design — see `docs/THREAT_MODEL.md` §7 layer 8.
//!
//! The actual rule machinery is intentionally not implemented yet. This stub
//! exists to lock the location and ownership in CODEOWNERS from day one, so
//! that future implementation cannot accidentally move it somewhere with
//! laxer review requirements.
