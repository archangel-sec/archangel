//! The append-only, hash-chained, signed audit log writer.
//!
//! Durability is prioritized over throughput (project priority: security >
//! performance). Every appended entry is flushed and `fsync`'d before the
//! call returns, so a crash cannot silently lose a recorded security event.
//! A torn final line left by a power loss is *detectable* by the verifier
//! and never produces a silently-accepted shorter chain.

use std::{
    fs::File,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use archangel_core::SessionId;

use crate::{
    entry::{genesis_prev_hash_hex, seal, AuditEvent, AuditRecord},
    error::AuditError,
    key::AuditKeypair,
};

/// A sink that durably persists one audit line at a time.
///
/// Implementors must guarantee that, once `commit_line` returns `Ok`, the
/// bytes have reached stable storage (or that durability is intentionally
/// not required, e.g. an in-memory test buffer).
pub trait DurableSink {
    /// Write the entire line and ensure it is durable before returning.
    fn commit_line(&mut self, line: &[u8]) -> Result<(), AuditError>;
}

/// File sink: append, flush, and `fsync` so the entry survives a crash.
impl DurableSink for File {
    fn commit_line(&mut self, line: &[u8]) -> Result<(), AuditError> {
        self.write_all(line)?;
        self.flush()?;
        self.sync_all()?;
        Ok(())
    }
}

/// In-memory sink for tests. Durability is a no-op by construction.
impl DurableSink for Vec<u8> {
    fn commit_line(&mut self, line: &[u8]) -> Result<(), AuditError> {
        self.extend_from_slice(line);
        Ok(())
    }
}

/// Milliseconds since the Unix epoch, saturating on a pre-epoch clock.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A live audit log. Holds the signing key and the running chain head.
///
/// Generic over the sink so the chaining logic can be unit-tested against
/// an in-memory buffer; production code uses [`AuditLog::open`] for a file.
pub struct AuditLog<S: DurableSink> {
    sink: S,
    keypair: AuditKeypair,
    next_seq: u64,
    prev_hash_hex: String,
}

impl AuditLog<File> {
    /// Open (creating if absent) an append-only log file at `path`.
    ///
    /// The file is opened `O_APPEND` with mode `0640`. A signed genesis
    /// entry anchoring the chain to `keypair`'s public key is written
    /// immediately. Use this only for a fresh log; resuming an existing
    /// log is a later milestone (requires a prior verification pass).
    pub fn open(path: &Path, keypair: AuditKeypair) -> Result<Self, AuditError> {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        opts.mode(0o640);

        let file = opts.open(path)?;
        Self::with_sink(file, keypair)
    }
}

impl<S: DurableSink> AuditLog<S> {
    /// Create a log over an arbitrary durable sink and write the genesis
    /// entry that anchors the chain to the keypair's public key.
    pub fn with_sink(sink: S, keypair: AuditKeypair) -> Result<Self, AuditError> {
        let mut log = Self {
            sink,
            keypair,
            next_seq: 0,
            prev_hash_hex: genesis_prev_hash_hex(),
        };
        log.append_genesis()?;
        Ok(log)
    }

    fn append_genesis(&mut self) -> Result<(), AuditError> {
        let event = AuditEvent::Genesis {
            audit_public_key: self.keypair.public_hex(),
        };
        self.append(event)
    }

    /// Append an event: build the record, sign it, link it into the chain,
    /// write the JSON line, then flush and fsync.
    pub fn append(&mut self, event: AuditEvent) -> Result<(), AuditError> {
        let record = AuditRecord {
            seq: self.next_seq,
            timestamp_ms: now_ms(),
            prev_hash: self.prev_hash_hex.clone(),
            event,
        };
        let (entry, _entry_hash) = seal(record, &self.keypair)?;

        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        self.sink.commit_line(&line)?;

        self.next_seq = self.next_seq.saturating_add(1);
        self.prev_hash_hex = entry.entry_hash;
        Ok(())
    }

    /// Convenience: record a free-form note.
    pub fn note(&mut self, message: impl Into<String>) -> Result<(), AuditError> {
        self.append(AuditEvent::Note {
            message: message.into(),
        })
    }

    /// Convenience: record the end of a session.
    pub fn session_ended(
        &mut self,
        session_id: SessionId,
        reason: impl Into<String>,
    ) -> Result<(), AuditError> {
        self.append(AuditEvent::SessionEnded {
            session_id,
            reason: reason.into(),
        })
    }

    /// The sequence number the next appended entry will receive.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The hex hash of the current chain head.
    #[must_use]
    pub fn head_hash_hex(&self) -> &str {
        &self.prev_hash_hex
    }
}
