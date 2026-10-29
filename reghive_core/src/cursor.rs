//! The **file-glob scan cursor** (§4 of the spec).
//!
//! A single hive parses whole, in memory — `notatin` materializes a per-file
//! cell index, so there is no resumable intra-file state. The only place an
//! externalized cursor appears is the *file-glob* level of `read_hive`: when a
//! glob spans many hives across HTTP-transport batch boundaries, the worker
//! carries this small playlist position so a fan-out that exceeds one batch
//! resumes at the right file/row rather than restarting.
//!
//! It is plain owned data — no handles, no `dyn`, no open file — so it
//! round-trips losslessly through `serialize -> bytes -> deserialize` (asserted
//! in a test, which is the HTTP-rehydration proof). A single-blob call carries
//! no cursor at all.

use serde::{Deserialize, Serialize};

/// A serde-serializable playlist position over a glob of hive files.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiveGlobCursor {
    /// Hives not yet started, in order.
    pub pending_files: Vec<String>,
    /// The hive currently in progress, if any.
    pub current_file: Option<String>,
    /// Rows already emitted from `current_file` (so a mid-file batch boundary
    /// resumes at the right row offset).
    pub emitted_in_current: u64,
}

impl HiveGlobCursor {
    /// Build a fresh cursor over an ordered list of files.
    pub fn new(mut files: Vec<String>) -> Self {
        let current_file = if files.is_empty() {
            None
        } else {
            Some(files.remove(0))
        };
        HiveGlobCursor {
            pending_files: files,
            current_file,
            emitted_in_current: 0,
        }
    }

    /// Serialize to JSON bytes for the SDK `opaque_data` channel.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Infallible for this plain struct; fall back to an empty cursor's bytes.
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Rehydrate from `opaque_data`. An empty slice yields a default (empty)
    /// cursor; malformed bytes also yield a default rather than erroring, so a
    /// corrupt cursor degrades to "start over" instead of crashing the scan.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return HiveGlobCursor::default();
        }
        serde_json::from_slice(bytes).unwrap_or_default()
    }

    /// Are there no files left to process at all?
    pub fn is_exhausted(&self) -> bool {
        self.current_file.is_none() && self.pending_files.is_empty()
    }

    /// Advance to the next file once the current one is fully emitted.
    pub fn advance_file(&mut self) {
        self.current_file = if self.pending_files.is_empty() {
            None
        } else {
            Some(self.pending_files.remove(0))
        };
        self.emitted_in_current = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_is_lossless() {
        let c = HiveGlobCursor {
            pending_files: vec!["b.dat".into(), "c.dat".into()],
            current_file: Some("a.dat".into()),
            emitted_in_current: 42,
        };
        let bytes = c.to_bytes();
        let back = HiveGlobCursor::from_bytes(&bytes);
        assert_eq!(c, back, "serialize -> bytes -> deserialize must be equal");
    }

    #[test]
    fn empty_bytes_is_default() {
        assert_eq!(HiveGlobCursor::from_bytes(&[]), HiveGlobCursor::default());
    }

    #[test]
    fn corrupt_bytes_degrade_to_default() {
        assert_eq!(
            HiveGlobCursor::from_bytes(b"not json at all"),
            HiveGlobCursor::default()
        );
    }

    #[test]
    fn new_and_advance() {
        let mut c = HiveGlobCursor::new(vec!["a".into(), "b".into()]);
        assert_eq!(c.current_file.as_deref(), Some("a"));
        c.advance_file();
        assert_eq!(c.current_file.as_deref(), Some("b"));
        c.advance_file();
        assert!(c.is_exhausted());
    }
}
